/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * Copyright (C) 2006-2010 Adele Team/LIG/Grenoble University, France
 */
package fede.workspace.domain;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;


/**
 * Cette implementation est plus rapide pour le tostring (2 � 3 fois) , la
 * lecture � partir d'un string (environ 10 fois).
 * 
 * A class that represents an immutable universally unique identifier
 * (CompactUUID). A CompactUUID represents a 128-bit value.
 * 
 * <p>
 * There exist different variants of these global identifiers. The methods of
 * this class are for manipulating the Leach-Salz variant, although the
 * constructors allow the creation of any variant of CompactUUID (described
 * below).
 * 
 * <p>
 * The layout of a variant 2 (Leach-Salz) CompactUUID is as follows:
 * 
 * The most significant long consists of the following unsigned fields:
 * 
 * <pre>
 * 0xFFFFFFFF00000000 time_low
 * 0x00000000FFFF0000 time_mid
 * 0x000000000000F000 version
 * 0x0000000000000FFF time_hi
 * </pre>
 * 
 * The least significant long consists of the following unsigned fields:
 * 
 * <pre>
 * 0xC000000000000000 variant
 * 0x3FFF000000000000 clock_seq
 * 0x0000FFFFFFFFFFFF node
 * </pre>
 * 
 * <p>
 * The variant field contains a value which identifies the layout of the
 * <tt>CompactUUID</tt>. The bit layout described above is valid only for a
 * <tt>CompactUUID</tt> with a variant value of 2, which indicates the
 * Leach-Salz variant.
 * 
 * <p>
 * The version field holds a value that describes the type of this
 * <tt>CompactUUID</tt>. There are four different basic types of
 * CompactUUIDs: time-based, DCE security, name-based, and randomly generated
 * CompactUUIDs. These types have a version value of 1, 2, 3 and 4,
 * respectively.
 * 
 * <p>
 * For more information including algorithms used to create <tt>CompactUUID</tt>s,
 * see the Internet-Draft <a
 * href="http://www.ietf.org/internet-drafts/draft-mealling-uuid-urn-03.txt">CompactUUIDs
 * and GUIDs</a> or the standards body definition at <a
 * href="http://www.iso.ch/cate/d2229.html">ISO/IEC 11578:1996</a>.
 * 
 * @version 1.14, 07/12/04
 * @since 1.5
 */
public final class CompactUUID implements java.io.Serializable,
		Comparable<CompactUUID> {

	
	
	public static final int STRING_LENGTH = 36;

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 5586287384551133835L;

	/*
	 * The most significant 64 bits of this CompactUUID.
	 * 
	 * @serial
	 */
	/** The most sig bits. */
	private final long mostSigBits;

	/*
	 * The least significant 64 bits of this CompactUUID.
	 * 
	 * @serial
	 */
	/** The least sig bits. */
	private final long leastSigBits;

	/*
	 * The random number generator used by this class to create random based
	 * CompactUUIDs.
	 */
	/** The number generator. */
	private static volatile SecureRandom numberGenerator = null;

	// Constructors and Factories

	/**
	 * Instantiates a new compact uuid.
	 * 
	 * @param name
	 *            the name
	 */
	public CompactUUID(String name) throws IllegalArgumentException {
		char[] buf = name.toCharArray();
		if (buf.length != 36)
			throw new IllegalArgumentException("Invalid CompactUUID string: " + name);
		
		long _mostSigBits = decode(buf, 0, 8);
		_mostSigBits <<= 16;
		_mostSigBits |= decode(buf, 9, 4);
		_mostSigBits <<= 16;
		_mostSigBits |= decode(buf, 14, 4);

		long _leastSigBits = decode(buf, 19, 4);
		_leastSigBits <<= 48;
		_leastSigBits |= decode(buf, 24, 12);

		mostSigBits  = _mostSigBits;
		leastSigBits = _leastSigBits;
	}
	
	
	/**
	 * Decode.
	 * 
	 * @param buf
	 *            the buf
	 * @param begin
	 *            the begin
	 * @param digits
	 *            the digits
	 * 
	 * @return the long
	 * 
	 * @throws IllegalArgumentException
	 *             the illegal argument exception
	 */
	public static long decode(char[] buf, int begin, int digits)
    throws IllegalArgumentException {

		long result = 0;
		long end = begin +digits;
		for (int i = begin; i < end; i++) {
			int v = buf[i];
			if (v >= '0' && v <= '9') {
				result = result *16 + (v - '0'); continue;
			} 
			if (v >= 'a' && v <= 'f') {
				result = result *16 + (v - 'a' +10 ); continue;
			}
			throw new IllegalArgumentException("invalid char "+new String(new char[] {(char)v}));
		}
		
		return result;

}
	/*
	 * Private constructor which uses a byte array to construct the new CompactUUID.
	 */
	/**
	 * Instantiates a new compact uuid.
	 * 
	 * @param data
	 *            the data
	 */
	private CompactUUID(byte[] data) {
		long msb = 0;
		long lsb = 0;
		assert data.length == 16;
		for (int i = 0; i < 8; i++)
			msb = (msb << 8) | (data[i] & 0xff);
		for (int i = 8; i < 16; i++)
			lsb = (lsb << 8) | (data[i] & 0xff);
		this.mostSigBits = msb;
		this.leastSigBits = lsb;
	}

	/**
	 * Instantiates a new compact uuid.
	 * 
	 * @param uuid
	 *            the uuid
	 */
	public CompactUUID(UUID uuid) {
		this(uuid.getMostSignificantBits(), uuid.getLeastSignificantBits());
	}
	
	/**
	 * Constructs a new <tt>CompactUUID</tt> using the specified data.
	 * <tt>mostSigBits</tt> is used for the most significant 64 bits of the
	 * <tt>CompactUUID</tt> and <tt>leastSigBits</tt> becomes the least
	 * significant 64 bits of the <tt>CompactUUID</tt>.
	 * 
	 * @param mostSigBits
	 *            the most sig bits
	 * @param leastSigBits
	 *            the least sig bits
	 */
	public CompactUUID(long mostSigBits, long leastSigBits) {
		this.mostSigBits = mostSigBits;
		this.leastSigBits = leastSigBits;
	}

	/**
	 * Static factory to retrieve a type 4 (pseudo randomly generated)
	 * CompactUUID.
	 * 
	 * The <code>CompactUUID</code> is generated using a cryptographically
	 * strong pseudo random number generator.
	 * 
	 * @return a randomly generated <tt>CompactUUID</tt>.
	 */
	public static CompactUUID randomUUID() {
		SecureRandom ng = numberGenerator;
		if (ng == null) {
			numberGenerator = ng = new SecureRandom();
		}

		byte[] randomBytes = new byte[16];
		ng.nextBytes(randomBytes);
		randomBytes[6] &= 0x0f; /* clear version */
		randomBytes[6] |= 0x40; /* set to version 4 */
		randomBytes[8] &= 0x3f; /* clear variant */
		randomBytes[8] |= 0x80; /* set to IETF variant */
		return new CompactUUID(randomBytes);
	}

	/**
	 * Static factory to retrieve a type 3 (name based) <tt>CompactUUID</tt>
	 * based on the specified byte array.
	 * 
	 * @param name
	 *            a byte array to be used to construct a <tt>CompactUUID</tt>.
	 * 
	 * @return a <tt>CompactUUID</tt> generated from the specified array.
	 */
	public static CompactUUID nameUUIDFromBytes(byte[] name) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException nsae) {
			throw new InternalError("MD5 not supported");
		}
		byte[] md5Bytes = md.digest(name);
		md5Bytes[6] &= 0x0f; /* clear version */
		md5Bytes[6] |= 0x30; /* set to version 3 */
		md5Bytes[8] &= 0x3f; /* clear variant */
		md5Bytes[8] |= 0x80; /* set to IETF variant */
		return new CompactUUID(md5Bytes);
	}

	/**
	 * Creates a <tt>CompactUUID</tt> from the string standard representation
	 * as described in the {@link #toString} method.
	 * 
	 * @param name
	 *            a string that specifies a <tt>CompactUUID</tt>.
	 * 
	 * @return a <tt>CompactUUID</tt> with the specified value.
	 * 
	 * @throws IllegalArgumentException
	 *             if name does not conform to the string representation as
	 *             described in {@link #toString}.
	 */
	public static CompactUUID fromString(String name) {
		return new CompactUUID(name);
	}

	// Field Accessor Methods

	/**
	 * Returns the least significant 64 bits of this CompactUUID's 128 bit
	 * value.
	 * 
	 * @return the least significant 64 bits of this CompactUUID's 128 bit
	 *         value.
	 */
	public long getLeastSignificantBits() {
		return leastSigBits;
	}

	/**
	 * Returns the most significant 64 bits of this CompactUUID's 128 bit value.
	 * 
	 * @return the most significant 64 bits of this CompactUUID's 128 bit value.
	 */
	public long getMostSignificantBits() {
		return mostSigBits;
	}

	
    
	// Object Inherited Methods

	/**
	 * Returns a <code>String</code> object representing this
	 * <code>CompactUUID</code>.
	 * 
	 * <p>
	 * The CompactUUID string representation is as described by this BNF :
	 * 
	 * <pre>
	 * CompactUUID                   = &lt;time_low&gt; &quot;-&quot; &lt;time_mid&gt; &quot;-&quot;
	 * &lt;time_high_and_version&gt; &quot;-&quot;
	 * &lt;variant_and_sequence&gt; &quot;-&quot;
	 * &lt;node&gt;
	 * time_low               = 4*&lt;hexOctet&gt;
	 * time_mid               = 2*&lt;hexOctet&gt;
	 * time_high_and_version  = 2*&lt;hexOctet&gt;
	 * variant_and_sequence   = 2*&lt;hexOctet&gt;
	 * node                   = 6*&lt;hexOctet&gt;
	 * hexOctet               = &lt;hexDigit&gt;&lt;hexDigit&gt;
	 * hexDigit               =
	 * &quot;0&quot; | &quot;1&quot; | &quot;2&quot; | &quot;3&quot; | &quot;4&quot; | &quot;5&quot; | &quot;6&quot; | &quot;7&quot; | &quot;8&quot; | &quot;9&quot;
	 * | &quot;a&quot; | &quot;b&quot; | &quot;c&quot; | &quot;d&quot; | &quot;e&quot; | &quot;f&quot;
	 * | &quot;A&quot; | &quot;B&quot; | &quot;C&quot; | &quot;D&quot; | &quot;E&quot; | &quot;F&quot;
	 * </pre>
	 * 
	 * @return a string representation of this <tt>CompactUUID</tt>.
	 */
	@Override
	public String toString() {
		char buf[] = new char[STRING_LENGTH];
		digits(mostSigBits >> 32, 8, buf, 0);
		buf[8] = '-';
		digits(mostSigBits >> 16, 4, buf, 9);
		buf[13] = '-';
		digits(mostSigBits, 4, buf, 14);
		buf[18] = '-';
		digits(leastSigBits >> 48, 4, buf, 19);
		buf[23] = '-';
		digits(leastSigBits, 12, buf, 24);
		return new String(buf);
	}
	
	
	/** The Constant radix. */
	final static int radix = 1 << 4;
	
	/** The Constant mask. */
	final static long mask = radix - 1;
	
	/** All possible chars for representing a number as a String. */
    final static private char[] digitsA = {
	'0' , '1' , '2' , '3' , '4' , '5' ,
	'6' , '7' , '8' , '9' , 'a' , 'b' ,
	'c' , 'd' , 'e' , 'f' 
    };
    
	
	/**
	 * Convert the integer to an unsigned number.
	 * 
	 * @param i
	 *            the i
	 * @param digits
	 *            the digits
	 * @param buf
	 *            the buf
	 * @param begin
	 *            the begin
	 */
    private static void digits(long i, int digits, char[] buf, int begin) {
	   for (int k = begin+digits; k != begin ;)  {
		    buf[--k] = digitsA[(int)(i & mask)];
		    i >>>= 4;
	   } 
    }

	/**
	 * Returns a hash code for this <code>CompactUUID</code>.
	 * 
	 * @return a hash code value for this <tt>CompactUUID</tt>.
	 */
	@Override
	public int hashCode() {
		return (int) ((mostSigBits >> 32) ^ mostSigBits ^ (leastSigBits >> 32) ^ leastSigBits);
	}

	/**
	 * Compares this object to the specified object. The result is <tt>true</tt>
	 * if and only if the argument is not <tt>null</tt>, is a
	 * <tt>CompactUUID</tt> object, has the same variant, and contains the
	 * same value, bit for bit, as this <tt>CompactUUID</tt>.
	 * 
	 * @param obj
	 *            the object to compare with.
	 * 
	 * @return <code>true</code> if the objects are the same;
	 *         <code>false</code> otherwise.
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof CompactUUID))
			return false;

		CompactUUID id = (CompactUUID) obj;
		return (mostSigBits == id.mostSigBits && leastSigBits == id.leastSigBits);
	}

	// Comparison Operations

	/**
	 * Compares this CompactUUID with the specified CompactUUID.
	 * 
	 * <p>
	 * The first of two CompactUUIDs follows the second if the most significant
	 * field in which the CompactUUIDs differ is greater for the first
	 * CompactUUID.
	 * 
	 * @param val
	 *            <tt>CompactUUID</tt> to which this <tt>CompactUUID</tt> is
	 *            to be compared.
	 * 
	 * @return -1, 0 or 1 as this <tt>CompactUUID</tt> is less than, equal to,
	 *         or greater than <tt>val</tt>.
	 */
	public int compareTo(CompactUUID val) {
		// The ordering is intentionally set up so that the CompactUUIDs
		// can simply be numerically compared as two numbers
		return (this.mostSigBits < val.mostSigBits ? -1
				: (this.mostSigBits > val.mostSigBits ? 1
						: (this.leastSigBits < val.leastSigBits ? -1
								: (this.leastSigBits > val.leastSigBits ? 1 : 0))));
	}
	
	
	
//	public static void main(String[] args) {
//		CompactUUID  uuid = randomUUID();
//		UUID uuid2 = new UUID(uuid.mostSigBits, uuid.leastSigBits);
//		long st1 = System.currentTimeMillis();
//		for (int i = 0; i < 10000; i++) {
//			uuid.toString();
//		}
//		long st2 = System.currentTimeMillis();
//		for (int i = 0; i < 10000 ; i++) {
//			uuid2.toString();
//		}
//		long st3 = System.currentTimeMillis();
//		
//		long r1 = st2-st1;
//		long r2 = st3-st2;
//		long d = r2-r1;
//		long dd = d / 10000;
//		System.out.println("result r1 : "+r1);
//		System.out.println("result r2 : "+r2);
//		System.out.println("result d : "+d);
//		System.out.println("result dd : "+dd);
//	}
	
	
//	public static void main(String[] args) {
//		for (int i = 0; i < 100; i++) {
//			CompactUUID uuid = randomUUID();
//			String st = uuid.toString();
//			CompactUUID uuid2 = new CompactUUID(st);
//			System.out.println("result  : " + uuid.equals(uuid2));
//		}
//	}
	
//	public static void main(String[] args) {
//		String[] st = new String[1000000];
//		for (int i = 0; i < st.length; i++) {
//			st[i] = randomUUID().toString();
//		}
//		long st1 = System.currentTimeMillis();
//		for (int i = 0; i < st.length; i++) {
//			new CompactUUID(st[i]);
//		}
//		long st2 = System.currentTimeMillis();
//		for (int i = 0; i < st.length ; i++) {
//			UUID.fromString(st[i]);
//		}
//		long st3 = System.currentTimeMillis();
//		
//		long r1 = st2-st1;
//		long r2 = st3-st2;
//		long d = r2-r1;
//		long dd = r2/r1;
//		System.out.println("result r1 : "+r1);
//		System.out.println("result r2 : "+r2);
//		System.out.println("result d : "+d);
//		System.out.println("result dd : "+dd);
//	}
}
