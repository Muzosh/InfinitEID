package temp;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 *
 * @author Hervé
 */
public class CryptedBankCard extends Applet {

    //CLA ID
    static final byte CLA_APPLET = (byte) 0xB0;

    //APPLET STATE
    static final byte STATE_INIT = 0;
    static final byte STATE_ISSUED = 1;

    ////INSTRUCTION
    //INIT
    static final byte INS_SET_PUBLIC_MODULUS = (byte) 0x01;
    static final byte INS_SET_PRIVATE_MODULUS = (byte) 0x02;
    static final byte INS_SET_PRIVATE_EXP = (byte) 0x03;
    static final byte INS_SET_PUBLIC_EXP = (byte) 0x04;
    static final byte INS_SET_OWNER_PIN = (byte) 0x05;
    static final byte INS_SET_ISSUED = (byte) 0x06;
    static final byte INS_TEST_PUBLIC_KEY = (byte) 0x07;
    static final byte INS_TEST_PRIVATE_KEY = (byte) 0x08;
    //ISSUED
    static final byte INS_VERIFICATION = (byte) 0x10;
    static final byte INS_CREDIT = (byte) 0x20;
    static final byte INS_DEBIT = (byte) 0x30;
    static final byte INS_BALANCE = (byte) 0x40;
    static final byte INS_SESSION_INIT = (byte) 0x50;

    ////STATUS WORD
    final static short SW_VERIFICATION_FAILED = 0x6300;
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    final static short SW_NEGATIVE_BALANCE = 0x6A85;

    final static short SW_PULBIC_KEY_FAILED = 0x6201;
    final static short SW_PULBIC_KEY_MOD_FAILED = 0x6211;
    final static short SW_PULBIC_KEY_EXP_FAILED = 0x6212;
    final static short SW_PRIVATE_KEY_FAILED = 0x6202;
    final static short SW_PRIVATE_KEY_MOD_FAILED = 0x6221;
    final static short SW_PRIVATE_KEY_EXP_FAILED = 0x6222;
    final static short SW_SESSION_KEY_FAILED = 0x6302;
    final static short SW_SESSION_KEY_NOT_VALID = 0x6303;
    final static short SW_MAGIC_KEY_NOT_VALID = 0x6304;
    final static short SW_ISSUED_FAILED = 0x6600;

    //DATA
    static final byte MAGIC_VALUE = (byte) 0x5f3759df;
    static final byte PIN_MAX_LIMIT = (byte) 0x03;
    static final byte PIN_MAX_SIZE = (byte) 0x04;
    private OwnerPIN ownerPIN;
    private short balance;
    private byte state;
    private byte[] sessionKey;
    byte[] tmp;

    //SECURITY
    DESKey desKey;
    RandomData randomDataGenerator;
    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;
    Cipher cipherRSA;
    Cipher cipherDES;
    Signature signature;
    private boolean publicKeyModulusSet = false;
    private boolean publicKeyExponentSet = false;
    private boolean privateKeyModulusSet = false;
    private boolean privateKeyExponentSet = false;

    //BEHAVIOR
    final static short MAX_BALANCE = 0x7FFF;
    final static byte MAX_TRANSACTION_AMOUNT = 127;
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    final static byte MAX_PIN_SIZE = (byte) 0x04;

    /**
     * Installs this applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptedBankCard(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected CryptedBankCard(byte[] bArray, short bOffset, byte bLength) {
        ownerPIN = new OwnerPIN(PIN_MAX_LIMIT, PIN_MAX_SIZE);
        //If install param can be modified
//        ownerPIN.update(bArray, bOffset, bLength);
        //Cipher
        cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        cipherDES = Cipher.getInstance(Cipher.ALG_DES_ECB_PKCS5, false);
        //Sign
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        //Session
        desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_2KEY, false);
        sessionKey = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        //Crypt
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        privateKey.clearKey();
        publicKey.clearKey();
        //RandomData
        randomDataGenerator = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        //Applet State
        state = STATE_INIT;
        //TMP
        tmp = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        //register
        register();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     */
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        //APPLET Selection
        if (selectingApplet()) {
            return;
        }

        //Read Bin Only
        if (buffer[ISO7816.OFFSET_CLA] != CLA_APPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (state) {
            case STATE_INIT:
                switch (ins) {
                    case INS_SET_PUBLIC_MODULUS:
                        insSetPublicModulus(apdu);
                        break;
                    case INS_SET_PRIVATE_MODULUS:
                        insSetPrivateModulus(apdu);
                        break;
                    case INS_SET_PUBLIC_EXP:
                        insSetPublicExp(apdu);
                        break;
                    case INS_TEST_PRIVATE_KEY:
                        insTestPrivateKey(apdu);
                        break;
                    case INS_TEST_PUBLIC_KEY:
                        insTestPublicKey(apdu);
                        break;
                    case INS_SET_PRIVATE_EXP:
                        insSetPrivateExp(apdu);
                        break;
                    case INS_SET_OWNER_PIN:
                        insSetOwnerPin(apdu);
                        break;
                    case INS_VERIFICATION:
                        insVerification(apdu);
                        break;
                    case INS_SET_ISSUED:
                        insSetIssued();
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                break;
            case STATE_ISSUED: {
                if (ins == INS_VERIFICATION) {
                    insVerification(apdu);
                } else if (ins == INS_SESSION_INIT) {
                    insSessionInit(apdu);
                } else {
                    if (!ownerPIN.isValidated()) {
                        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
                    }
                    if (!desKey.isInitialized()) {
                        ISOException.throwIt(SW_SESSION_KEY_NOT_VALID);
                    }
                    switch (ins) {
                        case INS_BALANCE:
                            insBalance(apdu);
                            break;
                        case INS_CREDIT:
                            insCredit(apdu);
                            break;
                        case INS_DEBIT:
                            insDebit(apdu);
                            break;
                        default:
                            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    }
                }
                break;
            }
            default:
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
    }

    /**
     * Return account balance
     *
     * @param apdu
     */
    private void insBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short outCryptBuffSize = 0;

        Util.setShort(tmp, (short) 0, balance);

        cipherDES.init(desKey, Cipher.MODE_ENCRYPT);
        outCryptBuffSize = cipherDES.doFinal(tmp, (short) 0, (short) 2, buffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength(outCryptBuffSize);
        apdu.sendBytes(ISO7816.OFFSET_CDATA, outCryptBuffSize);
    }

    /**
     * Make a credit action
     *
     * @param apdu
     */
    private void insCredit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        short outCryptBuffSize = 0;

        try {
            cipherDES.init(desKey, Cipher.MODE_DECRYPT);
            outCryptBuffSize = cipherDES.doFinal(buffer, ISO7816.OFFSET_CDATA, numBytes, tmp, (short) 0);

            if ((short) tmp.length > (short) 0) {
                byte creditAmount = tmp[0];
                if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
                    ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
                }

                if ((short) (balance + creditAmount) > MAX_BALANCE) {
                    ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
                }

                JCSystem.beginTransaction();
                balance = (short) (balance + creditAmount);
                JCSystem.commitTransaction();
            } else {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) ((short)0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) ((short)0x9200 + ex.getReason()));
        } finally {
            Util.arrayFillNonAtomic(tmp, (short) 0, outCryptBuffSize, (byte) 0);
        }
    }

    /**
     * Make a debit action
     *
     * @param apdu
     */
    private void insDebit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        short outCryptBuffSize = 0;

        try {
            cipherDES.init(desKey, Cipher.MODE_DECRYPT);
            outCryptBuffSize = cipherDES.doFinal(buffer, ISO7816.OFFSET_CDATA, numBytes, tmp, (short) 0);

            if ((short) tmp.length > (short) 0) {
                byte debitAmount = tmp[0];

                if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
                    ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
                }

                if ((short) (balance - debitAmount) < (short) 0) {
                    ISOException.throwIt(SW_NEGATIVE_BALANCE);
                }
                JCSystem.beginTransaction();
                balance = (short) (balance - debitAmount);
                JCSystem.commitTransaction();
            } else {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) ((short)0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) ((short)0x9200 + ex.getReason()));
        } finally {
            Util.arrayFillNonAtomic(tmp, (short) 0, outCryptBuffSize, (byte) 0);
        }
    }

    /**
     * Verify PIN
     *
     * @param apdu
     */
    private void insVerification(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        short outCryptBuffSize = 0;

        try {
            cipherDES.init(desKey, Cipher.MODE_DECRYPT);
            outCryptBuffSize = cipherDES.doFinal(buffer, ISO7816.OFFSET_CDATA, numBytes, tmp, (short) 0);
        } catch (CryptoException ex) {
            ISOException.throwIt((short) ((short)0x9100 + ex.getReason()));
        }

        if ((short) tmp.length <= (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (ownerPIN.check(tmp, (short) 0, (byte) outCryptBuffSize) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
        Util.arrayFillNonAtomic(tmp, (short) 0, outCryptBuffSize, (byte) 0);
    }

    //TODO Set return data
    /**
     * Set Ownper PIN Only used if install paramter can't be modified
     *
     * @param apdu
     */
    private void insSetOwnerPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        JCSystem.beginTransaction();
        ownerPIN.update(buffer, ISO7816.OFFSET_CDATA, (byte) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
        JCSystem.commitTransaction();
    }

    /**
     * Set Modulus of public key
     *
     * @param apdu
     * @param lc
     */
    void insSetPublicModulus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        try {
            if(!publicKeyModulusSet){
                JCSystem.beginTransaction();
                publicKey.setModulus(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
                JCSystem.commitTransaction();
                publicKeyModulusSet = true;
            } else {
                ISOException.throwIt((short) SW_PULBIC_KEY_MOD_FAILED);
            }
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) ((short)0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) ((short)0x9200 + ex.getReason()));
        }
    }

    /**
     * Set Modulus of private key
     *
     * @param apdu
     * @param lc
     */
    void insSetPrivateModulus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        try {
            if(!privateKeyModulusSet){
                JCSystem.beginTransaction();
                privateKey.setModulus(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
                JCSystem.commitTransaction();
                privateKeyModulusSet = true;
            } else {
                ISOException.throwIt((short) SW_PRIVATE_KEY_MOD_FAILED);
            }            
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) ((short)0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) ((short)0x9200 + ex.getReason()));
        }
    }

    /**
     * Set Exponent of private key
     *
     * @param apdu
     * @param lc
     */
    void insSetPrivateExp(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        try {
            if(!privateKeyExponentSet){
                JCSystem.beginTransaction();
                privateKey.setExponent(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
                JCSystem.commitTransaction();
                privateKeyExponentSet = true;
            } else {
                ISOException.throwIt((short) SW_PRIVATE_KEY_EXP_FAILED);
            }            
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) ((short)0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) ((short)0x9200 + ex.getReason()));
        }
    }

    /**
     * Set Exponent of public key
     *
     * @param apdu
     * @param lc
     */
    void insSetPublicExp(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        try {
            if(!publicKeyExponentSet){
                JCSystem.beginTransaction();
                publicKey.setExponent(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
                JCSystem.commitTransaction();
                publicKeyExponentSet = true;
            } else {
                ISOException.throwIt((short) SW_PULBIC_KEY_EXP_FAILED);
            }            
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) ((short)0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) ((short)0x9200 + ex.getReason()));
        }
    }

    void insSetIssued() {
        if(publicKeyExponentSet && 
                privateKeyExponentSet &&
                privateKeyModulusSet &&
                publicKeyModulusSet
                ){
            state = STATE_ISSUED;
        } else {
            ISOException.throwIt((short) SW_ISSUED_FAILED);
        }            
    }

    /**
     * Test if the Public key is initialized
     *
     * @param apdu
     */
    void insTestPublicKey(APDU apdu) {
        if (publicKey != null && !publicKey.isInitialized()) {
            ISOException.throwIt(SW_PULBIC_KEY_FAILED);
        }
    }

    /**
     * Test if the Private key is initialized
     *
     * @param apdu
     */
    void insTestPrivateKey(APDU apdu) {
        if (privateKey != null && !privateKey.isInitialized()) {
            ISOException.throwIt(SW_PRIVATE_KEY_FAILED);
        }
    }

    /**
     * Init the session Generate a random DES Key Crypt it Sign it
     *
     * @param apdu
     */
    void insSessionInit(APDU apdu) {
        try {
            randomDataGenerator.generateData(tmp, (short) 0, (short) 25);
            randomDataGenerator.setSeed(tmp, (short) 0, (short) 25);
            randomDataGenerator.generateData(sessionKey, (short) 0, (short) 16);
            JCSystem.beginTransaction();
            desKey.setKey(sessionKey, (short) 0);
            JCSystem.commitTransaction();

            byte[] buffer = apdu.getBuffer();
            short outCryptBuffSize = 0;
            short outSignBuffSize = 0;

            //Crypting
            cipherRSA.init(publicKey, Cipher.MODE_ENCRYPT);
            outCryptBuffSize = cipherRSA.doFinal(sessionKey, (short) 0, (short) 16, buffer, ISO7816.OFFSET_CDATA);

            //Signing
            signature.init(privateKey, Signature.MODE_SIGN);
            outSignBuffSize = signature.sign(buffer, ISO7816.OFFSET_CDATA, outCryptBuffSize, buffer, (short) (ISO7816.OFFSET_CDATA + outCryptBuffSize));

            short totalSize = (short) (outCryptBuffSize + outSignBuffSize);
            apdu.setOutgoing();
            apdu.setOutgoingLength(totalSize);
            apdu.sendBytes(ISO7816.OFFSET_CDATA, totalSize);

        } catch (Exception ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt(SW_SESSION_KEY_FAILED);
        } finally {
            Util.arrayFillNonAtomic(sessionKey, (short) 0, (short) 16, (byte) 0);
            Util.arrayFillNonAtomic(tmp, (short) 0, (short) 25, (byte) 0);
        }
    }

    public boolean select() {
        //If card is locked 
        if (ownerPIN.getTriesRemaining() == 0) {
            return false;
        }
        return true;
    }

    public void deselect() {
        //Reset Tries value
        ownerPIN.reset();
    }
}
