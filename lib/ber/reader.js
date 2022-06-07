'use strict';

const assert = require('assert');
const ASN1 = require('./types');
const { InvalidAsn1Error } = require('./errors');


///--- API

class Reader {
	constructor(data) {
		if (!Buffer.isBuffer(data))
			throw new TypeError('data must be a node Buffer');

		this._buf = data;
		this._size = data.length;

		// These hold the "current" state
		this._len = 0;
		this._offset = 0;
	}

	get length() { return this._len; }
	get offset() { return this._offset; }
	get remain() { return this._size - this._offset; }
	get buffer() { return this._buf.subarray(this._offset, this._size); }


	/**
 	 * Reads a single byte and advances offset; you can pass in `true` to make this
 	 * a "peek" operation (i.e., get the byte, but don't advance the offset).
 	 *
 	 * @param {Boolean} peek true means don't move offset.
 	 * @return {Number} the next byte, null if not enough data.
 	 */
	readByte(peek) {
		if (this._size - this._offset < 1)
			return null;

		let b = this._buf[this._offset] & 0xff;

		if (!peek)
			this._offset += 1;

		return b;
	}


	peek() {
		return this.readByte(true);
	}


	/**
 	 * Reads a (potentially) variable length off the BER buffer.  This call is
 	 * not really meant to be called directly, as callers have to manipulate
 	 * the internal buffer afterwards.
 	 *
 	 * As a result of this call, you can call `Reader.length`, until the
 	 * next thing called that does a readLength.
 	 *
 	 * @return {Number} the amount of offset to advance the buffer.
 	 * @throws {InvalidAsn1Error} on bad ASN.1
 	 */
	readLength(offset) {
		if (offset === undefined)
			offset = this._offset;

		if (offset >= this._size)
			return null;

		let lenB = this._buf[offset++] & 0xff;
		if (lenB === null)
			return null;

		if ((lenB & 0x80) == 0x80) {
			lenB &= 0x7f;

			if (lenB == 0)
				throw InvalidAsn1Error('Indefinite length not supported');

			// Caused problems for node-net-snmp issue #172
			// if (lenB > 4)
			// 	throw InvalidAsn1Error('encoding too long');

			if (this._size - offset < lenB)
				return null;

			this._len = 0;
			for (let i = 0; i < lenB; i++) {
				this._len *= 256;
				this._len += (this._buf[offset++] & 0xff);
			}

		} else {
			// Wasn't a variable length
			this._len = lenB;
		}

		return offset;
	}


	/**
 	 * Parses the next sequence in this BER buffer.
 	 *
 	 * To get the length of the sequence, call `Reader.length`.
 	 *
 	 * @return {Number} the sequence's tag.
 	 */
	readSequence(tag) {
		let seq = this.peek();
		if (seq === null)
			return null;
		if (tag !== undefined && tag !== seq)
			throw InvalidAsn1Error(`Expected tag 0x${tag.toString(16)}, got 0x${seq.toString(16)}`);

		let o = this.readLength(this._offset + 1); // stored in `length`
		if (o === null)
			return null;

		this._offset = o;
		return seq;
	}


	readInt(tag /* = ASN1.Integer */) {
		return this._readTag(tag);
	}


	readBoolean(tag = ASN1.Boolean) {
		return this._readTag(tag) !== 0;
	}


	readEnumeration(tag = ASN1.Enumeration) {
		return this._readTag(tag);
	}


	readBuffer(tag = ASN1.OctetString) {
		let b = this.peek();
		if (b === null)
			return null;

		if (b !== tag)
			throw InvalidAsn1Error(`Expected tag 0x${tag.toString(16)}, got 0x${b.toString(16)}`);

		let o = this.readLength(this._offset + 1); // stored in `length`
		if (o === null)
			return null;

		if (this.length > this._size - o)
			return null;

		this._offset = o + this.length;

		return this._buf.subarray(o, this._offset);
	}

	readString(tag, encoding) {
		if (typeof tag === 'string' && encoding === undefined) {
			encoding = tag;
			tag = undefined;
		}
		let buf = this.readBuffer(tag || ASN1.OctetString);
		if (buf === null || encoding === true)
			return buf;
		return buf.toString(encoding || 'utf-8');
	}

	readOID(tag = ASN1.OID) {
		let b = this.readString(tag, true);
		if (b === null)
			return null;

		let values = [];
		let value = 0;

		for (let byte of b) {
			value <<= 7;
			value += byte & 0x7f;
			if ((byte & 0x80) == 0) {
				values.push(value >>> 0);
				value = 0;
			}
		}

		value = values.shift();
		values.unshift(value % 40);
		values.unshift((value / 40) >> 0);

		return values.join('.');
	}

	readBitString(tag = ASN1.BitString) {
		let b = this.peek();
		if (b === null)
			return null;

		if (b !== tag)
			throw InvalidAsn1Error(`Expected tag 0x${tag.toString(16)}, got 0x${b.toString(16)}`);

		let o = this.readLength(this._offset + 1);

		if (o === null)
			return null;

		if (this.length > this._size - o)
			return null;

		this._offset = o;

		if (this.length === 0)
			return '';

		let ignoredBits = this._buf[this._offset++];

		let bitStringOctets = this._buf.slice(this._offset, this._offset + this.length - 1);
		let bitString = (parseInt(bitStringOctets.toString('hex'), 16).toString(2)).padStart(bitStringOctets.length * 8, '0');
		this._offset += this.length - 1;

		return bitString.substring(0, bitString.length - ignoredBits);
	}

	_readTag(tag) {
		let b = this.peek();

		if (b === null)
			return null;

		if (tag !== undefined && b !== tag)
			throw InvalidAsn1Error(`Expected tag 0x${tag.toString(16)}, got 0x${b.toString(16)}`);

		let o = this.readLength(this._offset + 1); // stored in `length`
		if (o === null)
			return null;

		if (this.length === 0)
			throw InvalidAsn1Error('Zero-length integer');

		if (this.length > this._size - o)
			return null;
		this._offset = o;

		let value = this._buf.readInt8(this._offset++);
		for (let i = 1; i < this.length; i++) {
			value *= 256;
			value += this._buf[this._offset++];
		}

		if ( ! Number.isSafeInteger(value) )
			throw InvalidAsn1Error('Integer not representable as javascript number');

		return value;
	}

}



///--- Exported API

module.exports = Reader;
