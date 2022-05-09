package temp;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import webeidapplet.WebeidApplet;

public class WebeidAppletDev extends Applet implements ExtendedLength {
	/* Card-specific configuration */
	public static final boolean DEF_EXT_APDU = false;
	public static final boolean DEF_PRIVATE_KEY_IMPORT_ALLOWED = false;

	/* References */
	public final static byte AUTH_KEYPAIR_REFERENCE = (byte) 0x01;
	public final static byte SIGNING_KEYPAIR_REFERENCE = (byte) 0x02;
	public final static byte KEYPAIR_GENERATION_REFERENCE = (byte) 0x08;
	public final static byte GET_PUBLIC_KEY_REFERENCE = (byte) 0x09;

	private static KeyPair authKeypair;
	private static KeyPair signKeypair;
	private static Signature ecc;
	private static byte[] authcert;
	private static byte[] signcert;

	private short[] runtime_fields;
	private short selectedfile = 0;
	private byte[] ram_buf = null;
	private short[] ram_chaining_cache = null;

	/* Other constants */
	// "ram_buf" is used for:
	// * GET RESPONSE (caching for response APDUs)
	// * Command Chaining or extended APDUs (caching of command APDU data)
	private static final short RAM_BUF_SIZE = (short) 0x600;
	// "ram_chaining_cache" is used for:
	// - Caching of the amount of bytes remainung.
	// - Caching of the current send position.
	// - Determining how many operations had previously been performed in the chain
	// (re-use CURRENT_POS)
	// - Caching of the current INS (Only one chain at a time, for one specific
	// instruction).
	private static final short RAM_CHAINING_CACHE_SIZE = (short) 4;
	private static final short RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING = (short) 0;
	private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_POS = (short) 1;
	private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_INS = (short) 2;
	private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2 = (short) 3;

	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		(new WebeidApplet()).register();
	}

	private WebeidApplet() {
		// Create keypairs
		authKeypair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		signKeypair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

		// prepare NIST secp265r1 curve for auth key pair
		ECPublicKey authPublic = (ECPublicKey) authKeypair.getPublic();
		authPublic.setFieldFP(secp256r1.p, (short) 0, (short) secp256r1.p.length);
		authPublic.setA(secp256r1.a, (short) 0, (short) secp256r1.a.length);
		authPublic.setB(secp256r1.b, (short) 0, (short) secp256r1.b.length);
		authPublic.setG(secp256r1.g, (short) 0, (short) secp256r1.g.length);
		authPublic.setR(secp256r1.r, (short) 0, (short) secp256r1.r.length);
		authPublic.setK(secp256r1.k);

		// prepare NIST secp265r1 curve for auth key pair
		ECPublicKey signPublic = (ECPublicKey) signKeypair.getPublic();
		signPublic.setFieldFP(secp256r1.p, (short) 0, (short) secp256r1.p.length);
		signPublic.setA(secp256r1.a, (short) 0, (short) secp256r1.a.length);
		signPublic.setB(secp256r1.b, (short) 0, (short) secp256r1.b.length);
		signPublic.setG(secp256r1.g, (short) 0, (short) secp256r1.g.length);
		signPublic.setR(secp256r1.r, (short) 0, (short) secp256r1.r.length);
		signPublic.setK(secp256r1.k);

		// Initialize Certificate fields
		// TODO: how big fields need to be? default cert with es256 is 1033 bytes
		authcert = new byte[0x600];
		Util.arrayFillNonAtomic(authcert, (short) 0, (short) authcert.length, (byte) 0x00);
		signcert = new byte[0x600];
		Util.arrayFillNonAtomic(signcert, (short) 0, (short) signcert.length, (byte) 0x00);

		// Initialize operational fields
		// making transient array of length 1 for storing current selected file
		// is only way of how to keep it in RAM, not EEPROM
		runtime_fields = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
		ecc = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		ram_buf = JCSystem.makeTransientByteArray(RAM_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
		ram_chaining_cache = JCSystem.makeTransientShortArray(RAM_CHAINING_CACHE_SIZE, JCSystem.CLEAR_ON_DESELECT);
	}

	public boolean select() {
		runtime_fields[selectedfile] = FileHelper.FID_3F00;
		return true;
	}

	public void deselect() {
		runtime_fields[selectedfile] = FileHelper.FID_3F00;
	}

	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		byte ins = buffer[IsoHelper.OFFSET_INS];

		if (selectingApplet())
			return;

		// No secure messaging at the moment
		if (apdu.isSecureMessagingCLA()) {
			ISOException.throwIt(IsoHelper.SW_SECURE_MESSAGING_NOT_SUPPORTED);
		}

		// Command chaining checks
		if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] != (short) 0 || isCommandChainingCLA(apdu)) {
			short p1p2 = Util.getShort(buffer, IsoHelper.OFFSET_P1);
			/*
			 * Command chaining only for:
			 * - STORE CERTIFICATE
			 * when not using extended APDUs.
			 */
			if (DEF_EXT_APDU || (ins != IsoHelper.INS_STORE_CERTIFICATE)) {
				ISOException.throwIt(IsoHelper.SW_COMMAND_CHAINING_NOT_SUPPORTED);
			}

			if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] == (short) 0
					&& ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] == (short) 0) {
				/* A new chain is starting - set the current INS and P1P2. */
				if (ins == (short) 0) {
					ISOException.throwIt(IsoHelper.SW_INS_NOT_SUPPORTED);
				}
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] = (short) ins;
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] = p1p2;
			} else if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] != ins
					|| ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] != p1p2) {
				/*
				 * The current chain is not yet completed,
				 * but an apdu not part of the chain had been received.
				 */
				ISOException.throwIt(IsoHelper.SW_COMMAND_NOT_ALLOWED_GENERAL);
			} else if (!isCommandChainingCLA(apdu)) {
				/* A chain is ending, set the current INS and P1P2 to zero to indicate that. */
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] = 0;
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] = 0;
			}
		}

		// If the card expects a GET RESPONSE, no other operation should be requested.
		if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > 0 && ins != IsoHelper.INS_GET_RESPONSE) {
			ISOException.throwIt(IsoHelper.SW_COMMAND_NOT_ALLOWED_GENERAL);
		}

		if (apdu.isISOInterindustryCLA()) {
			switch (ins) {
				case IsoHelper.INS_SELECT:
					selectFile(apdu, buffer);
					break;
				case IsoHelper.INS_INTERNAL_AUTHENTICATE:
					internalAuthenticate(apdu, buffer);
					break;
				case IsoHelper.INS_READ_BINARY:
					readBinary(apdu, buffer);
					break;
				case IsoHelper.INS_PERFORM_SIGNATURE:
					performSignature(apdu, buffer);
					break;
				case IsoHelper.INS_GENERATE_KEYPAIR:
					generateKeypair(apdu, buffer);
					break;
				case IsoHelper.INS_GET_PUBLIC_KEY:
					getPublicKey(apdu, buffer);
					break;
				case IsoHelper.INS_STORE_CERTIFICATE:
					storeCertificate(apdu, buffer);
					break;
				case IsoHelper.INS_GET_RESPONSE:
					storeCertificate(apdu, buffer);
					break;
				default:
					ISOException.throwIt(IsoHelper.SW_INS_NOT_SUPPORTED);
			}
		} else {
			ISOException.throwIt(IsoHelper.SW_CLA_NOT_SUPPORTED);
		}
	}

	private void selectFile(APDU apdu, byte[] buffer) {
		byte p1 = buffer[IsoHelper.OFFSET_P1];
		byte p2 = buffer[IsoHelper.OFFSET_P2];

		if (p1 == 0x00) {
			runtime_fields[selectedfile] = FileHelper.FID_3F00;
		} else if (buffer[IsoHelper.OFFSET_LC] == (byte) 0x02) {
			// len = length of data, should be lc
			apdu.setIncomingAndReceive();

			short fid = Util.makeShort(buffer[IsoHelper.OFFSET_CDATA], buffer[IsoHelper.OFFSET_CDATA + 1]);
			switch (fid) {
				case FileHelper.FID_3F00:
				case FileHelper.FID_AACE:
				case FileHelper.FID_DDCE:
					runtime_fields[selectedfile] = fid;
					break;
				default:
					ISOException.throwIt(IsoHelper.SW_FILE_NOT_FOUND);
					break;
			}
		}

		// Send FCI if asked
		if (p2 == 0x04 || p2 == 0x00) {
			switch (runtime_fields[selectedfile]) {
				case FileHelper.FID_3F00:
					sendSmallData(apdu, FileHelper.fci_mf, (short) 0, (short) FileHelper.fci_mf.length);
					break;
				case FileHelper.FID_AACE:
					sendSmallData(apdu, FileHelper.fci_aace, (short) 0, (short) FileHelper.fci_aace.length);
					break;
				case FileHelper.FID_DDCE:
					sendSmallData(apdu, FileHelper.fci_ddce, (short) 0, (short) FileHelper.fci_ddce.length);
					break;
				default:
					ISOException.throwIt(IsoHelper.SW_FILE_NOT_FOUND);
			}
		}
	}

	private void readBinary(APDU apdu, byte[] buffer) {
		short offset = Util.makeShort(buffer[IsoHelper.OFFSET_P1], buffer[IsoHelper.OFFSET_P2]);
		// len = le
		short len = apdu.setOutgoing();

		if (runtime_fields[selectedfile] == FileHelper.FID_AACE) {
			sendSmallData(apdu, authcert, offset, len);
		} else if (runtime_fields[selectedfile] == FileHelper.FID_DDCE) {
			sendSmallData(apdu, authcert, offset, len);
		} else {
			ISOException.throwIt(IsoHelper.SW_FILE_NOT_FOUND);
		}
	}

	private void internalAuthenticate(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		ecc.init(authKeypair.getPrivate(), Signature.MODE_SIGN);
		// TODO: maybe will need offsetcdata + 1 and len - 1 since Lc is not added in
		// app - but probably not
		short len2 = ecc.signPreComputedHash(buffer, IsoHelper.OFFSET_CDATA, len, ram_buf, (short) 0);
		sendSmallData(apdu, ram_buf, (short) 0, len2);
	}

	private void performSignature(APDU apdu, byte[] buffer) {
		byte p1 = buffer[IsoHelper.OFFSET_P1];
		byte p2 = buffer[IsoHelper.OFFSET_P2];
		short len = apdu.setIncomingAndReceive();

		short parameters = Util.makeShort(p1, p2);
		if (parameters == (short) 0x9E9A) {
			ecc.init(signKeypair.getPrivate(), Signature.MODE_SIGN);
			short len2 = ecc.signPreComputedHash(buffer, IsoHelper.OFFSET_CDATA, len, ram_buf, (short) 0);
			sendSmallData(apdu, ram_buf, (short) 0, len2);
		} else {
			ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
		}
	}

	private void generateKeypair(APDU apdu, byte[] buffer) {
		byte p1 = buffer[IsoHelper.OFFSET_P1];
		byte p2 = buffer[IsoHelper.OFFSET_P2];
		KeyPair keypair = null;

		if (p1 == AUTH_KEYPAIR_REFERENCE) {
			keypair = authKeypair;
		} else if (p1 == SIGNING_KEYPAIR_REFERENCE) {
			keypair = signKeypair;
		}

		// Generation
		if (p2 == KEYPAIR_GENERATION_REFERENCE) {
			keypair.genKeyPair();
			ISOException.throwIt(IsoHelper.SW_NO_ERROR);
		} else {
			ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
		}
	}

	private void getPublicKey(APDU apdu, byte[] buffer) {
		byte p1 = buffer[IsoHelper.OFFSET_P1];
		byte p2 = buffer[IsoHelper.OFFSET_P2];
		KeyPair keypair = null;

		if (p1 == AUTH_KEYPAIR_REFERENCE) {
			keypair = authKeypair;
		} else if (p1 == SIGNING_KEYPAIR_REFERENCE) {
			keypair = signKeypair;
		}

		if (p2 == GET_PUBLIC_KEY_REFERENCE) {
			short len = ((ECPublicKey) keypair.getPublic()).getW(buffer, (short) 0);
			apdu.setOutgoingAndSend((short) 0, len);
		} else {
			ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
		}
	}

	private void storeCertificate(APDU apdu, byte[] buffer) {
		byte p1 = buffer[IsoHelper.OFFSET_P1];
		short recvLen = doChainingOrExtAPDU(apdu);

		if (!apdu.isCommandChainingCLA()) {
			if (p1 == (byte) 0x01) {
				Util.arrayCopyNonAtomic(ram_buf, (short) 0, authcert, (short) 0,
						recvLen);
			} else if (p1 == (byte) 0x02) {
				Util.arrayCopyNonAtomic(ram_buf, (short) 0, signcert, (short) 0,
						recvLen);
			} else
				ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
		}
	}

	/**
	 * \brief Parse the apdu's CLA byte to determine if the apdu is the first or
	 * second-last part of a chain.
	 *
	 * The Java Card API version 2.2.2 has a similar method
	 * (APDU.isCommandChainingCLA()), but tests have shown
	 * that some smartcard platform's implementations are wrong (not according to
	 * the JC API specification),
	 * specifically, but not limited to, JCOP 2.4.1 R3.
	 *
	 * \param apdu The apdu.
	 *
	 * \return true If the apdu is the [1;last[ part of a command chain,
	 * false if there is no chain or the apdu is the last part of the chain.
	 */
	static boolean isCommandChainingCLA(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		return ((byte) (buf[0] & (byte) 0x10) == (byte) 0x10);
	}

	/**
	 * \brief Send the data from ram_buf, using either extended APDUs or GET
	 * RESPONSE.
	 *
	 * \param apdu The APDU object, in STATE_OUTGOING state.
	 *
	 * \param pos The position in ram_buf at where the data begins
	 *
	 * \param len The length of the data to be sent. If zero, 9000 will be
	 * returned
	 */
	private void sendLargeData(APDU apdu, short pos, short len) {
		if (len <= 0) {
			ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = 0;
			ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
			ISOException.throwIt(IsoHelper.SW_NO_ERROR);
		}

		if ((short) (pos + len) > RAM_BUF_SIZE) {
			ISOException.throwIt(IsoHelper.SW_UNKNOWN);
		}

		if (DEF_EXT_APDU) {
			apdu.setOutgoingLength(len);
			apdu.sendBytesLong(ram_buf, pos, len);
		} else {
			// We have 256 Bytes send-capacity per APDU.
			// Send directly from ram_buf, then prepare for chaining.
			short sendLen = len > 256 ? 256 : len;
			apdu.setOutgoingLength(sendLen);
			apdu.sendBytesLong(ram_buf, pos, sendLen);
			short bytesLeft = (short) (len - sendLen);
			if (bytesLeft > 0) {
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = bytesLeft;
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) (pos + sendLen);
				short getRespLen = bytesLeft > 256 ? 256 : bytesLeft;
				ISOException.throwIt((short) (IsoHelper.SW_BYTES_REMAINING_00 | getRespLen));
				// The next part of the data is now in ram_buf, metadata is in
				// ram_chaining_cache.
				// It can be fetched by the host via GET RESPONSE.
			} else {
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = 0;
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
				ISOException.throwIt(IsoHelper.SW_NO_ERROR);
			}
		}
	}

	public void sendSmallData(APDU apdu, byte[] data, short offset, short len) {
		// Return what is left if application asked for more
		if ((short) (offset + len) > (short) data.length)
			len = (short) (data.length - offset);

		// Copy data
		Util.arrayCopyNonAtomic(data, offset, apdu.getBuffer(), (short) 0, len);

		// Check if setOutgoing() has already been called
		if (apdu.getCurrentState() == APDU.STATE_OUTGOING) {
			apdu.setOutgoingLength(len);
			apdu.sendBytes((short) 0, len);
		} else {
			apdu.setOutgoingAndSend((short) 0, len);
		}
		// Exit normal code flow
		ISOException.throwIt(IsoHelper.SW_NO_ERROR);
	}

	/**
	 * \brief Receive the data sent by chaining or extended apdus and store it in
	 * ram_buf.
	 *
	 * This is a convienience method if large data has to be accumulated using
	 * command chaining
	 * or extended apdus. The apdu must be in the INITIAL state, i.e.
	 * setIncomingAndReceive()
	 * might not have been called already.
	 *
	 * \param apdu The apdu object in the initial state.
	 *
	 * \throw ISOException SW_WRONG_LENGTH
	 */
	private short doChainingOrExtAPDU(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		short recvLen = apdu.setIncomingAndReceive();
		short offset_cdata = apdu.getOffsetCdata();

		// Receive data (short or extended).
		while (recvLen > 0) {
			if ((short) (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] + recvLen) > RAM_BUF_SIZE) {
				ISOException.throwIt(IsoHelper.SW_WRONG_LENGTH);
			}
			Util.arrayCopyNonAtomic(buf, offset_cdata, ram_buf,
					ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS], recvLen);
			ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] += recvLen;
			recvLen = apdu.receiveBytes(offset_cdata);
		}

		if (isCommandChainingCLA(apdu)) {
			// We are still in the middle of a chain, otherwise there would not have been a
			// chaining CLA.
			// Make sure the caller does not forget to return as the data should only be
			// interpreted
			// when the chain is completed (when using this method).
			ISOException.throwIt(IsoHelper.SW_NO_ERROR);
			return (short) 0;
		} else {
			// Chain has ended or no chaining.
			// We did receive the data, everything is fine.
			// Reset the current position in ram_buf.
			recvLen = (short) (recvLen + ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]);
			ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
			return recvLen;
		}
	}

	/**
	 * \brief Process the GET RESPONSE APDU (INS=C0).
	 *
	 * If there is content available in ram_buf that could not be sent in the last
	 * operation,
	 * the host should use this APDU to get the data. The data is cached in ram_buf.
	 *
	 * \param apdu The GET RESPONSE apdu.
	 *
	 * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_UNKNOWN,
	 * SW_CORRECT_LENGTH.
	 */
	private void processGetResponse(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short le = apdu.setOutgoing();

		if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] <= (short) 0) {
			ISOException.throwIt(IsoHelper.SW_CONDITIONS_NOT_SATISFIED);
		}

		short expectedLe = ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > 256 ? 256
				: ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING];
		if (le != expectedLe) {
			ISOException.throwIt((short) (IsoHelper.SW_CORRECT_LENGTH_00 | expectedLe));
		}

		sendLargeData(apdu, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS],
				ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]);
	}

	public static interface IsoHelper extends javacard.framework.ISO7816 {
		// CLAs
		public final static byte CLA_ISO_STANDARD = (byte) 0x00;
		public final static byte CLA_PROPRIETARY = (byte) 0x80;

		// INSs
		public final static byte INS_VERIFY_PIN = (byte) 0x20;
		public final static byte INS_CHANGE_PIN = (byte) 0x24;
		public final static byte INS_UNBLOCK = (byte) 0x2C;
		public final static byte INS_RESET_RETRY_COUNTER = (byte) 0x2C;
		public final static byte INS_SELECT = (byte) 0xA4;
		public final static byte INS_READ_BINARY = (byte) 0xB0;
		public final static byte INS_UPDATE_BINARY = (byte) 0xD6;
		public final static byte INS_ERASE_BINARY = (byte) 0x0E;
		public final static byte INS_READ_RECORD = (byte) 0xB2;
		public final static byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte) 0x22;
		public final static byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
		public final static byte INS_MUTUAL_AUTHENTICATE = (byte) 0x82;
		public final static byte INS_GET_CHALLENGE = (byte) 0x84;
		public final static byte INS_UPDATE_RECORD = (byte) 0xDC;
		public final static byte INS_APPEND_RECORD = (byte) 0xE2;
		public final static byte INS_GET_DATA = (byte) 0xCA;
		public final static byte INS_PUT_DATA = (byte) 0xDA;
		public final static byte INS_CREATE_FILE = (byte) 0xE0;
		public final static byte INS_DELETE_FILE = (byte) 0xE4;
		public final static byte INS_GENERATE_KEYPAIR = (byte) 0x01;
		public final static byte INS_PERFORM_SIGNATURE = (byte) 0x2A;
		public final static byte INS_GET_PUBLIC_KEY = (byte) 0x02;
		public final static byte INS_STORE_CERTIFICATE = (byte) 0x03;
		public final static byte INS_GET_RESPONSE = (byte) 0xC0;

		// SWs that are not in ISO7816 interface
		public final static short SW_ALGORITHM_NOT_SUPPORTED = (short) 0x9484;
		public final static short SW_WRONG_PIN_0_TRIES_LEFT = (short) 0x63C0;
		public final static short SW_INCONSISTENT_P1P2 = (short) 0x6A87;
		public final static short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;
		public final static short SW_WRONG_LENGTH_00 = (short) 0x6C00;
		public final static short SW_COMMAND_NOT_ALLOWED_GENERAL = 0x6900;

		// offsets
		public final static byte OFFSET_PIN_HEADER = OFFSET_CDATA;
		public final static byte OFFSET_PIN_DATA = OFFSET_CDATA + 1;
		public final static byte OFFSET_SECOND_PIN_HEADER = OFFSET_CDATA + 8;
	}

	public static class secp256r1 {
		public static final byte[] p = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

		public static final byte[] a = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFC };

		public static final byte[] b = new byte[] { (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA,
				(byte) 0x3A, (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76,
				(byte) 0x98, (byte) 0x86, (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC,
				(byte) 0x53, (byte) 0xB0, (byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27,
				(byte) 0xD2, (byte) 0x60, (byte) 0x4B };

		public static final byte[] g = new byte[] { (byte) 0x04, (byte) 0x6B,
				(byte) 0x17, (byte) 0xD1, (byte) 0xF2,
				(byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8, (byte) 0xBC,
				(byte) 0xE6, (byte) 0xE5,
				(byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2, (byte) 0x77, (byte) 0x03,
				(byte) 0x7D, (byte) 0x81,
				(byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0, (byte) 0xF4, (byte) 0xA1,
				(byte) 0x39, (byte) 0x45,
				(byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96, (byte) 0x4F, (byte) 0xE3,
				(byte) 0x42, (byte) 0xE2,
				(byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B, (byte) 0x8E, (byte) 0xE7,
				(byte) 0xEB, (byte) 0x4A,
				(byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16, (byte) 0x2B, (byte) 0xCE,
				(byte) 0x33, (byte) 0x57,
				(byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE, (byte) 0xCB, (byte) 0xB6,
				(byte) 0x40, (byte) 0x68,
				(byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5 };

		public static final byte[] r = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7,
				(byte) 0x17, (byte) 0x9E, (byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC,
				(byte) 0x63, (byte) 0x25, (byte) 0x51 };

		public static final short k = (short) 0x01;
	}

	public static class FileHelper {
		public static final short FID_3F00 = (short) 0x3F00;
		public static final short FID_AACE = (short) 0xAACE;
		public static final short FID_DDCE = (short) 0xDDCE;

		// FCI bytes;
		// https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/
		// TODO: implement this
		public static final byte[] fci_mf = new byte[] { (byte) 0x6F, (byte) 0x26, (byte) 0x82, (byte) 0x01,
				(byte) 0x38,
				(byte) 0x83, (byte) 0x02, (byte) 0x3F, (byte) 0x00, (byte) 0x84, (byte) 0x02, (byte) 0x4D, (byte) 0x46,
				(byte) 0x85, (byte) 0x02, (byte) 0x57, (byte) 0x3E, (byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1,
				(byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x02, (byte) 0x81, (byte) 0x08, (byte) 0xD2, (byte) 0x76,
				(byte) 0x00, (byte) 0x00, (byte) 0x28, (byte) 0xFF, (byte) 0x05, (byte) 0x2D, (byte) 0x82, (byte) 0x03,
				(byte) 0x03, (byte) 0x00, (byte) 0x00 };
		public static final byte[] fci_aace = new byte[] { (byte) 0x62, (byte) 0x18, (byte) 0x82, (byte) 0x01,
				(byte) 0x01,
				(byte) 0x83, (byte) 0x02, (byte) 0xAA, (byte) 0xCE, (byte) 0x85, (byte) 0x02, (byte) 0x06, (byte) 0x00,
				(byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1, (byte) 0x08, (byte) 0x8B, (byte) 0x06, (byte) 0x00,
				(byte) 0x30, (byte) 0x03, (byte) 0x06, (byte) 0x00, (byte) 0x01 };
		public static final byte[] fci_ddce = new byte[] { (byte) 0x62, (byte) 0x18, (byte) 0x82, (byte) 0x01,
				(byte) 0x01,
				(byte) 0x83, (byte) 0x02, (byte) 0xDD, (byte) 0xCE, (byte) 0x85, (byte) 0x02, (byte) 0x06, (byte) 0x00,
				(byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1, (byte) 0x08, (byte) 0x8B, (byte) 0x06, (byte) 0x00,
				(byte) 0x30, (byte) 0x03, (byte) 0x06, (byte) 0x00, (byte) 0x01 };
	}
}
