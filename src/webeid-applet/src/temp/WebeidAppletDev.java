package temp;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class WebeidAppletDev extends Applet {
	/* Card-specific configuration */
	public static final boolean DEF_EXT_APDU = false;
	public static final boolean DEF_PRIVATE_KEY_IMPORT_ALLOWED = false;

	// pin references
	public final static byte AUTH_PIN_REFERENCE = (byte) 0x01;
	public final static byte SIGNING_PIN_REFERENCE = (byte) 0x02;
	public final static byte ADMIN_PIN_REFERENCE = (byte) 0x03;

	// PIN:
	public static final byte PIN_MAX_TRIES = 3;
	public static final byte PIN_MIN_LENGTH = 4;
	public static final byte PIN_MAX_LENGTH = 16;
	// PUK:
	public static final boolean PUK_MUST_BE_SET = true;
	public static final byte PUK_MAX_TRIES = 5;
	public static final byte PUK_LENGTH = 16;

	// previous APDU types
	public final static byte PREVIOUS_APDU_TYPE_OTHER = (byte) 0x00;
	public final static byte PREVIOUS_APDU_TYPE_AUTH_PIN = (byte) 0x01;
	public final static byte PREVIOUS_APDU_TYPE_SIGN_PIN = (byte) 0x02;
	public final static byte PREVIOUS_APDU_TYPE_ADMIN_PIN = (byte) 0x03;

	/* Card/Applet lifecycle states */
	private static final byte STATE_CREATION = (byte) 0x00; // No restrictions, PUK not set yet.
	private static final byte STATE_INITIALISATION = (byte) 0x01; // PUK set, PIN not set yet. PUK may not be changed.
	private static final byte STATE_OPERATIONAL_ACTIVATED = (byte) 0x05; // PIN is set, data is secured.

	/* Other constants */
	// "ram_buf" is used for:
	// * GET RESPONSE (caching for response APDUs)
	// * Command Chaining or extended APDUs (caching of command APDU data)
	private static final short RAM_BUF_SIZE = (short) 660;

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

	private byte state;
	private OwnerPIN authPin = null;
	private OwnerPIN signPin = null;
	private OwnerPIN puk = null;
	private static KeyPair authKeypair;
	private static KeyPair signKeypair;
	private static Signature ecc;
	private static byte[] authcert;
	private static byte[] signcert;
	private static byte[] previousApduType;

	private short[] runtime_fields;
	private short selectedfile = 0;
	private byte[] ram_buf = null;
	private short[] ram_chaining_cache = null;

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
		ECPublicKey signPublic = (ECPublicKey) authKeypair.getPublic();
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
		authPin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
		signPin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
		ram_buf = JCSystem.makeTransientByteArray(RAM_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
		ram_chaining_cache = JCSystem.makeTransientShortArray(RAM_CHAINING_CACHE_SIZE, JCSystem.CLEAR_ON_DESELECT);
		state = STATE_CREATION;
	}

	public boolean select() {
		runtime_fields[selectedfile] = FileHelper.FID_3F00;
		return true;
	}

	public void deselect() {
		runtime_fields[selectedfile] = FileHelper.FID_3F00;
		authPin.reset();
		signPin.reset();
		if (puk != null) {
			puk.reset();
		}
	}

	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();

		if (selectingApplet())
			return;

		// No secure messaging at the moment
		if (apdu.isSecureMessagingCLA()) {
			ISOException.throwIt(IsoHelper.SW_SECURE_MESSAGING_NOT_SUPPORTED);
		}

		switch (buffer[IsoHelper.OFFSET_CLA]) {
			case IsoHelper.CLA_ISO_STANDARD:
				process_command(apdu, buffer);
				break;
			case IsoHelper.CLA_PROPRIETARY: // setting/getting values
				process_maitenance_command(apdu, buffer);
				break;
			default:
				ISOException.throwIt(IsoHelper.SW_CLA_NOT_SUPPORTED);
				break;
		}
	}

	private void process_command(APDU apdu, byte[] buffer) {
		switch (buffer[IsoHelper.OFFSET_INS]) {
			case IsoHelper.INS_SELECT:
				selectFile(apdu, buffer);
				break;
			case IsoHelper.INS_MANAGE_SECURITY_ENVIRONMENT:
				// TODO: maybe implement this? look in other projects
				// Internal state is implicitly known
				APDUHelper.throwIt(IsoHelper.SW_NO_ERROR);
				break;
			case IsoHelper.INS_INTERNAL_AUTHENTICATE:
				len = apdu.setIncomingAndReceive();
				ecc.init(authKeypair.getPrivate(), Signature.MODE_SIGN);
				// TODO: maybe will need offsetcdata + 1 and len - 1 since Lc is not added in
				// app - but probably not
				len2 = ecc.signPreComputedHash(buffer, IsoHelper.OFFSET_CDATA, len, ram, (short) 0);
				APDUHelper.send_array(ram, (short) 0, len2);
			case IsoHelper.INS_VERIFY_PIN:
				verifyPin(apdu, buffer);
				break;
			case IsoHelper.INS_CHANGE_PIN:
				changePin(apdu, buffer);
				break;
			case IsoHelper.INS_UNBLOCK:
				unblock(apdu, buffer);
				break;
			case IsoHelper.INS_READ_BINARY:
				readBinary(apdu, buffer);
				break;
			case IsoHelper.INS_PERFORM_SIGNATURE:
				len = apdu.setIncomingAndReceive();
				// Sign and decrypt
				short parameters = Util.makeShort(p1, p2);
				if (parameters == (short) 0x9E9A) {
					ecc.init(signKeypair.getPrivate(), Signature.MODE_SIGN);
					len2 = ecc.signPreComputedHash(buffer, IsoHelper.OFFSET_CDATA, len, ram, (short) 0);
					APDUHelper.send_array(ram, (short) 0, len2);
				} else {
					APDUHelper.throwIt(IsoHelper.SW_INCORRECT_P1P2);
				}
				break;
			default:
				APDUHelper.throwIt(IsoHelper.SW_INS_NOT_SUPPORTED);
		}
	}

	private void process_maitenance_command(APDU apdu, byte[] buffer) {
		byte p1 = buffer[IsoHelper.OFFSET_P1];
		byte p2 = buffer[IsoHelper.OFFSET_P2];

		short len = 0;
		short offset = 0;
		byte[] src = null;
		KeyPair keypair = null;

		switch (buffer[IsoHelper.OFFSET_INS]) {
			case (byte) 0x01: // generate key pair
				if (p1 == (byte) 0x01) { // auth
					keypair = authKeypair;
				} else if (p1 == (byte) 0x02) { // sign
					keypair = signKeypair;
				}
				// Generation
				if (p2 == (byte) 0x08) {
					keypair.genKeyPair();
					ISOException.throwIt(IsoHelper.SW_NO_ERROR);
				} else {
					ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
				}
				break;
			case (byte) 0x02: // get public key
				if (p1 == (byte) 0x01) { // auth
					keypair = authKeypair;
				} else if (p1 == (byte) 0x02) { // sign
					keypair = signKeypair;
				}

				if (p2 == (byte) 0xD5) {
					len = ((ECPublicKey) keypair.getPublic()).getW(buffer, (short) 0);
				} else {
					ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
				}
				apdu.setOutgoingAndSend((short) 0, len);
				break;
			case (byte) 0x03: // store certificate
				len = apdu.setIncomingAndReceive();
				offset = Util.makeShort(buffer[IsoHelper.OFFSET_CDATA], buffer[IsoHelper.OFFSET_CDATA + 1]);
				if (p1 == (byte) 0x01) {
					Util.arrayCopyNonAtomic(buffer, (short) (IsoHelper.OFFSET_CDATA + 2), authcert, offset,
							(short) (len - 2));
				} else if (p1 == (byte) 0x02) {
					Util.arrayCopyNonAtomic(buffer, (short) (IsoHelper.OFFSET_CDATA + 2), signcert, offset,
							(short) (len - 2));
				} else
					ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
				break;
			case (byte) 0x04: // PIN codes
				// There are other known response codes like 0x6985 (old and new are PIN same),
				// 0x6402
				// (re-entered PIN is different) that only apply during PIN change
				// TODO: re-implement this
				if (p2 == (byte) 0x00) { // puk
					src = puk;
				} else if (p2 == (byte) 0x01) {
					src = pin1;
				} else if (p2 == (byte) 0x02) {
					src = pin2;
				} else
					ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
				if (buffer[IsoHelper.OFFSET_LC] == (byte) 0x00) { // get
					APDUHelper.send_array(src, (short) 0, (short) (src[0] + 1));
				} else { // set
					len = apdu.setIncomingAndReceive();
					Util.arrayCopyNonAtomic(buffer, IsoHelper.OFFSET_LC, src, (short) 0, len);
					src[0] = (byte) len;
				}
				break;
			case IsoHelper.INS_RESET_RETRY_COUNTER:
				// TODO: implement this?
				APDUHelper.throwIt(IsoHelper.SW_NO_ERROR);
				break;
			default:
				ISOException.throwIt(IsoHelper.SW_INS_NOT_SUPPORTED);
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
	 * \return true If the apdu is the [1;last] part of a command chain,
	 * false if there is no chain or the apdu is the last part of the chain.
	 */
	static boolean isCommandChainingCLA(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		return ((byte) (buf[0] & (byte) 0x10) == (byte) 0x10);
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
					APDUHelper.throwIt(IsoHelper.SW_FILE_NOT_FOUND);
					break;
			}
		} else if (p1 == 0x04) {
			// TODO: maybe will not be needed?
			short len = apdu.setIncomingAndReceive();
			if (!JCSystem.getAID().partialEquals(buffer, IsoHelper.OFFSET_CDATA, (byte) len)) {
				APDUHelper.throwIt(IsoHelper.SW_FILE_NOT_FOUND);
			}
		}

		// Send FCI if asked
		if (p2 == 0x04 || p2 == 0x00) {
			switch (runtime_fields[selectedfile]) {
				case FileHelper.FID_3F00:
					APDUHelper.send_array(FileHelper.fci_mf);
					break;
				case FileHelper.FID_AACE:
					APDUHelper.send_array(FileHelper.fci_aace);
					break;
				case FileHelper.FID_DDCE:
					APDUHelper.send_array(FileHelper.fci_ddce);
					break;
				default:
					APDUHelper.throwIt(IsoHelper.SW_FILE_NOT_FOUND);
			}
		}
	}

	private void readBinary(APDU apdu, byte[] buffer) {
		byte p1 = buffer[IsoHelper.OFFSET_P1];
		byte p2 = buffer[IsoHelper.OFFSET_P2];
		short offset = Util.makeShort(p1, p2);
		// len = le
		short len = apdu.setOutgoing();
		if (runtime_fields[selectedfile] == FileHelper.FID_AACE) {
			APDUHelper.send_array(authcert, offset, len);
		} else if (runtime_fields[selectedfile] == FID_DDCE) {
			APDUHelper.send_array(signcert, offset, len);
		} else {
			APDUHelper.throwIt(IsoHelper.SW_FILE_NOT_FOUND);
		}
	}

	private void verifyPin(APDU apdu, byte[] buffer) {
		short offset_cdata;
		short lc;

		// P1P2 0001 only at the moment. (key-reference 01 = PIN)
		if (buffer[IsoHelper.OFFSET_P1] != 0x00
				|| (buffer[IsoHelper.OFFSET_P2] != 0x01 && buffer[IsoHelper.OFFSET_P2] != 0x02)) {
			ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
		}

		// Bytes received must be Lc.
		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(IsoHelper.SW_WRONG_LENGTH);
		}
		offset_cdata = apdu.getOffsetCdata();

		// Lc might be 0, in this case the caller checks if verification is required.
		if ((lc > 0 && (lc < PIN_MIN_LENGTH) || lc > PIN_MAX_LENGTH)) {
			ISOException.throwIt(IsoHelper.SW_WRONG_LENGTH);
		}

		// Caller asks if verification is needed.
		if (lc == 0
				&& state != STATE_CREATION
				&& state != STATE_INITIALISATION) {
			// Verification required, return remaining tries.
			ISOException.throwIt((short) (SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
		} else if (lc == 0
				&& (state == STATE_CREATION
						|| state == STATE_INITIALISATION)) {
			// No verification required.
			ISOException.throwIt(IsoHelper.SW_NO_ERROR);
		}

		// Pad the PIN if not done by caller, so no garbage from the APDU will be part
		// of the PIN.
		Util.arrayFillNonAtomic(buffer, (short) (offset_cdata + lc), (short) (PIN_MAX_LENGTH - lc), (byte) 0x00);

		// Check the PIN.
		if (!pin.check(buffer, offset_cdata, PIN_MAX_LENGTH)) {
			fs.setUserAuthenticated(false);
			ISOException.throwIt((short) (SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
		} else {
			fs.setUserAuthenticated(true);
		}
	}

	private void changePin(APDU apdu, byte[] buffer) {
		/*
		 * The previous APDU type has to be overwritten in every possible exit
		 * path out of this function
		 */
		// check P2
		if (buffer[IsoHelper.OFFSET_P2] != (byte) 0x01) {
			setPreviousApduType(IsoHelper.PREVIOUS_APDU_TYPE_OTHER);
			ISOException.throwIt(IsoHelper.SW_INCORRECT_P1P2);
		}
		// P1 determines whether it is user or administrator PIN change
		switch (buffer[IsoHelper.OFFSET_P1]) {
			case (byte) 0x00:
				setPreviousApduType(IsoHelper.PREVIOUS_APDU_TYPE_OTHER);
				userChangePin(apdu, buffer);
				break;
			case (byte) 0x01:
				administratorChangePin(apdu, buffer);
				break;
			default:
				setPreviousApduType(IsoHelper.PREVIOUS_APDU_TYPE_OTHER);
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				break;
		}
	}

	private void setPreviousApduType(byte type) {
		previousApduType[0] = type;
	}

	private byte getPreviousApduType() {
		return previousApduType[0];
	}

	private void checkPin(OwnerPIN pin, byte[] buffer) {
		if (pin.check(buffer, IsoHelper.OFFSET_PIN_HEADER, PIN_SIZE) == true)
			return;
		short tries = pin.getTriesRemaining();
		/*
		 * create the correct exception the status word is of the form 0x63Cx
		 * with x the number of tries left
		 */
		ISOException.throwIt((short) (IsoHelper.SW_WRONG_PIN_0_TRIES_LEFT | tries));
	}

	public interface IsoHelper extends javacard.framework.ISO7816 {
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
		public final static byte INS_GENERATE_ASYMMETRIC_KEY_PAIR = (byte) 0x46;
		public final static byte INS_PERFORM_SIGNATURE = (byte) 0x2A;

		// SWs that are not in ISO7816 interface
		public final static short SW_ALGORITHM_NOT_SUPPORTED = (short) 0x9484;
		public final static short SW_WRONG_PIN_0_TRIES_LEFT = (short) 0x63C0;
		public final static short SW_INCONSISTENT_P1P2 = (short) 0x6A87;
		public final static short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;
		public final static short SW_WRONG_LENGTH_00 = (short) 0x6C00;

		// offsets
		public final static byte OFFSET_PIN_HEADER = OFFSET_CDATA;
		public final static byte OFFSET_PIN_DATA = OFFSET_CDATA + 1;
		public final static byte OFFSET_SECOND_PIN_HEADER = OFFSET_CDATA + 8;
	}

	public interface secp256r1 {
		public final byte[] p = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

		public final byte[] a = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFC };

		public final byte[] b = new byte[] { (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA,
				(byte) 0x3A, (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76,
				(byte) 0x98, (byte) 0x86, (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC,
				(byte) 0x53, (byte) 0xB0, (byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27,
				(byte) 0xD2, (byte) 0x60, (byte) 0x4B };

		public final byte[] g = new byte[] { (byte) 0x04, (byte) 0x6B,
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

		public final byte[] r = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7,
				(byte) 0x17, (byte) 0x9E, (byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC,
				(byte) 0x63, (byte) 0x25, (byte) 0x51 };

		public final short k = (short) 0x01;
	}

	public interface FileHelper {
		// Less interesting objects
		// File identifiers that are used by baastarkvara
		public final short FID_3F00 = (short) 0x3F00;
		public final short FID_AACE = (short) 0xAACE;
		public final short FID_DDCE = (short) 0xDDCE;

		// FCI bytes;
		// https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/
		// TODO: implement this
		public final byte[] fci_mf = new byte[] { (byte) 0x6F, (byte) 0x26, (byte) 0x82, (byte) 0x01, (byte) 0x38,
				(byte) 0x83, (byte) 0x02, (byte) 0x3F, (byte) 0x00, (byte) 0x84, (byte) 0x02, (byte) 0x4D, (byte) 0x46,
				(byte) 0x85, (byte) 0x02, (byte) 0x57, (byte) 0x3E, (byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1,
				(byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x02, (byte) 0x81, (byte) 0x08, (byte) 0xD2, (byte) 0x76,
				(byte) 0x00, (byte) 0x00, (byte) 0x28, (byte) 0xFF, (byte) 0x05, (byte) 0x2D, (byte) 0x82, (byte) 0x03,
				(byte) 0x03, (byte) 0x00, (byte) 0x00 };
		public final byte[] fci_aace = new byte[] { (byte) 0x62, (byte) 0x18, (byte) 0x82, (byte) 0x01, (byte) 0x01,
				(byte) 0x83, (byte) 0x02, (byte) 0xAA, (byte) 0xCE, (byte) 0x85, (byte) 0x02, (byte) 0x06, (byte) 0x00,
				(byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1, (byte) 0x08, (byte) 0x8B, (byte) 0x06, (byte) 0x00,
				(byte) 0x30, (byte) 0x03, (byte) 0x06, (byte) 0x00, (byte) 0x01 };
		public final byte[] fci_ddce = new byte[] { (byte) 0x62, (byte) 0x18, (byte) 0x82, (byte) 0x01, (byte) 0x01,
				(byte) 0x83, (byte) 0x02, (byte) 0xDD, (byte) 0xCE, (byte) 0x85, (byte) 0x02, (byte) 0x06, (byte) 0x00,
				(byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1, (byte) 0x08, (byte) 0x8B, (byte) 0x06, (byte) 0x00,
				(byte) 0x30, (byte) 0x03, (byte) 0x06, (byte) 0x00, (byte) 0x01 };
	}

	public static final class APDUHelper {

		public static void send_array(byte[] array) {
			send_array(array, (short) 0, (short) array.length);
		}

		public static void send_array(byte[] array, short offset, short len) {
			// get buffer
			APDU apdu = APDU.getCurrentAPDU(); // TODO: dont use this
			// This method is failsafe.
			if ((short) (offset + len) > (short) array.length)
				len = (short) (array.length - offset);
			// Copy data
			Util.arrayCopyNonAtomic(array, offset, apdu.getBuffer(), (short) 0, len);
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

		public static void send(short offset, short len) {
			APDU apdu = APDU.getCurrentAPDU();
			apdu.setOutgoingAndSend(offset, len);
			// Exit normal code flow
			ISOException.throwIt(IsoHelper.SW_NO_ERROR);
		}

		public static void throwIt(short sw) {
			ISOException.throwIt(sw);
		}
	}
}
