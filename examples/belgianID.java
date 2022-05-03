package be.msec.smartcard;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.*;

public class IdentityCard extends Applet {
	
	//private RSAPrivateKey privateKeyCommon;
	
	private short offset_0 = 0;
	private short offset_1 = 1;
	private short offset_2 = 2;
    private short keySizeInBytes = 64;
    //private short keySizeInBits = 512;
	
    private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
    private static final byte VALIDATE_PIN_INS = 0x22;
    private static final byte GET_SERIAL_INS = 0x24;

    private final static byte PIN_TRY_LIMIT = (byte) 0x03;
    private final static byte PIN_SIZE = (byte) 0x04;

    private static final int APDU_MAX_BUFF_SIZE = 128;

    //from M -> SC
    private static final byte HELLO_DIS = 0x40;
    private static final byte NEW_TIME = 0x41;
    private static final byte NEW_SERVICE_CERT = 0x42;
    private static final byte SERVICE_CERT_DONE = 0x43;
    private static final byte SERVICE_AUTH = 0x44;
    private static final byte SERVICE_RESP_CHALLENGE = 0x45;
    private static final byte SERVICE_CHALLENGE = 0x46;
    private static final byte NEW_QUERY = 0x47;
    private static final byte QUERY_DONE = 0x48;
    private static final byte GET_QUERY = 0x49;


    //from SC -> M
    private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    private final static short SW_ABORT = 0x6339;
    private final static short SW_REQ_REVALIDATION = 0x6340;
    private final static short SW_SIG_NO_MATCH = 0x6341;
    private final static short SW_CERT_EXPIRED = 0x6342;
    private final static short SW_VERIFICATION_FAILED = 0x6343;

    //last variables
    static byte[] last_message = new byte[0];
    static byte[] last_signature = new byte[0];
    static byte[] lastCert = new byte[0];
    static RSAPublicKey last_pk;
    static byte[] last_modulus;
    static byte[] last_exp = hexStringToByteArray("010001");

    // timestamps
    private byte[] lastValidationTime = new byte[]{0x00}; // (20)000101000000
    private byte[] lastValidationTimeString = hexStringToByteArray("303030313031303030303030"); // (20)000101000000
    private final static long VALIDATION_TIME = 24 * 60 * 60;
    //private final static byte TIMESTAMP_SIZE = (byte) 0x12;

    //certificates - start \\\\
    private String common_key_hex;
    private String common_cert_hex;
    private String gov_cert_hex;
    private String ca_cert_hex;

    private byte[] common_key_bytes;
    private byte[] common_cert_bytes;
    private byte[] common_modulus_bytes;
    private byte[] common_exp_priv_bytes;
    //private byte[] common_exp_pub_bytes;
    //private byte[] common_sig_bytes;
    private byte[] gov_cert_bytes;
    private byte[] gov_modulus_bytes;
    private byte[] gov_exp_pub_bytes;
    private byte[] ca_cert_bytes;
    //private byte[] ca_modulus_bytes;
    //private byte[] ca_exp_pub_bytes;

    //different domains
    private final static String DOMAIN_DEFAULT_HEX = "64656661756C74";
    private final static byte[] DOMAIN_DEFAULT_BYTES = hexStringToByteArray(DOMAIN_DEFAULT_HEX);
    private final static String DOMAIN_SUPERMARKET_HEX = "65436F6D6D65726365";
    private final static byte[] DOMAIN_SUPERMARKET_BYTES = hexStringToByteArray(DOMAIN_SUPERMARKET_HEX);
    private final static String DOMAIN_EGOV_HEX = "65476F76";
    private final static byte[] DOMAIN_EGOV_BYTES = hexStringToByteArray(DOMAIN_EGOV_HEX);
    private final static String DOMAIN_SOCNET_HEX = "536F634E6574";
    private final static byte[] DOMAIN_SOCNET_BYTES = hexStringToByteArray(DOMAIN_SOCNET_HEX);

    //storage to process certificate
    static byte[] lastCertIssuer;
    static byte[] last_cert_issuer_domain;
    static byte[] last_cert_subject_cn;
    static byte[] last_cert_subject_domain;
    static byte[] last_cert_valid_after;
    static byte[] last_cert_valid_before;
    static byte[] last_cert_modulus;
    static byte[] last_cert_exponent;
    static byte[] last_cert_signature;
    static byte[] last_cert_tbs;

    static AESKey last_symm_key;
    static byte[] last_symm_key_bytes;
    static byte[] last_symm_key_encrypted;
    static RSAPublicKey last_cert_pk;
    static byte[] last_challenge;
    static byte[] last_challenge_with_subject;
    static byte[] last_challenge_with_subject_encrypted;
    static byte[] serviceAuthResponse;
    static byte[] last_challenge_response_aes;
    static byte[] last_challenge_response;
    long chall_resp_long;
    long chall_long;
    static byte[] last_server_challenge;
    static byte[] last_server_challenge_resp;
    static byte[] last_server_challenge_resp_encrypted;
    boolean hasCheckAuthContent = false;

    static byte[] last_query = new byte[0];
    static byte[] queryItem = new byte[0];

    private RSAPrivateKey common_sk = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
    //private RSAPublicKey common_pk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
    private RSAPublicKey gov_pk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
    //private RSAPublicKey ca_pk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);

    private final static int LENGTH_RSA_512_BYTES = KeyBuilder.LENGTH_RSA_512 / 8;
    private final static int LENGTH_AES_128_BYTES = KeyBuilder.LENGTH_AES_128 / 8;
    private Cipher cipher;
    private RandomData srng;
    //private Signature sig;
    private MessageDigest md;

    byte[] queryResult;
    byte[] query_result_encrypted;

    //certificates - end \\\\

    //keywords - start \\\\
    private final static String MODULUS_HEX = "024100";
    private final static byte[] MODULUS_BYTES = hexStringToByteArray(MODULUS_HEX);
    private final static String EXPONENT_HEX = "010240";
    private final static byte[] EXPONENT_BYTES = hexStringToByteArray(EXPONENT_HEX);
    private final static String SIGNATURE_HEX = "300D06092A864886F70D0101050500034100";
    private final static byte[] SIGNATURE_BYTES = hexStringToByteArray(SIGNATURE_HEX);
    //private final static String CERT_HEX = "308201"; // +1byte
    //private final static byte[] CERT_BYTES = hexStringToByteArray(CERT_HEX);
    private final static String DOMAIN_HEX = "060A0992268993F22C64040D0C";
    private final static byte[] DOMAIN_BYTES = hexStringToByteArray(DOMAIN_HEX);
    private final static String CN_HEX = "06035504030C";
    private final static byte[] CN_BYTES = hexStringToByteArray(CN_HEX);
    private final static String VALIDITY_HEX = "170D";
    private final static byte[] VALIDITY_BYTES = hexStringToByteArray(VALIDITY_HEX);

    //keywords - end \\\\

    //Data fields
    private final static byte NYM_IDX = (byte) 0;
    private final static byte NAME_IDX = (byte) 1;
    private final static byte ADDRESS_IDX = (byte) 2;
    private final static byte COUNTRY_IDX = (byte) 3;
    private final static byte BIRTHDATE_IDX = (byte) 4;
    private final static byte AGE_IDX = (byte) 5;
    private final static byte GENDER_IDX = (byte) 6;
    private final static byte PICTURE_IDX = (byte) 7;
    private final static byte[] DOMAIN_DEFAULT_AUTH = new byte[]{0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
    private final static byte[] DOMAIN_SUPERMARKET_AUTH = new byte[]{0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00};
    private final static byte[] DOMAIN_EGOV_AUTH = new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00};
    private final static byte[] DOMAIN_SOCNET_AUTH = new byte[]{0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01};
    //Mocking DATA
    private static byte[] NYM = null;
    private final static byte[] NAME = "Tom Alex".getBytes();
    private final static byte[] ADDRESS = "Kerkstraat 1, 9340 Lede".getBytes();
    private final static byte[] COUNTRY = "BE".getBytes();
    private final static byte[] BIRTHDATE = "18/02/1978".getBytes();
    private final static byte[] AGE = "39".getBytes();
    private final static byte[] GENDER = "M".getBytes();
    private final static byte[] PICTURE = "\n|==========|\n|          |\n|  O   O   |\n|    0     |\n| \\      / |\n|  ------  |\n\\         /\n  =======".getBytes();

    private Boolean isServiceAuthenticated = false;
    private Boolean isPinValidated = false;

    private byte[] serial = new byte[]{0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05};
    private OwnerPIN pin;

    private IdentityCard() {
        System.out.println("IdentityCard");

		/*
         * During instantiation of the applet, all objects are created. In this
		 * example, this is the 'pin' object.
		 */
        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
        pin.update(new byte[]{0x01, 0x02, 0x03, 0x04}, offset_0, PIN_SIZE);

        // government certificates
        //sha256
        //gov_cert_hex = "3082026D30820217A003020102020101300D06092A864886F70D01010B05003075310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310B3009060355040A0C024341310C300A060355040B0C03565542310B300906035504030C0243413118301606092A864886F70D01090116096361407675622E6265301E170D3137303530373134333135355A170D3230303230313134333135355A304F310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310C300A060355040A0C03565542310C300A06035504030C03474F56305C300D06092A864886F70D0101010500034B003048024100ABF3C4E671EE773FACFBCAA04BFBE1EB3A740973AB007BE981481E003481136761616ACE72E39B0913D2B47C14F21FB7E7F2248894CC999201631F53E74B0AED0203010001A381B73081B4301D0603551D0E04160414DB722F8E48391E6DE3DB64B1ADCAF24173E12021301F0603551D23041830168014FAFF2F7386E7AF24F46EA5EA734F703CD8E3407B30090603551D1304023000300B0603551D0F0404030205A0302C0603551D110425302382096C6F63616C686F737487047F000001871000000000000000000000000000000001302C06096086480186F842010D041F161D4F70656E53534C2047656E657261746564204365727469666963617465300D06092A864886F70D01010B0500034100801A09D3127F386B32E5B3F946871DD1C28254814BC2C11535BD67C49FED21E03074308B41F367D6536C641949BD4F63ADAFE21680F6F98D7EA6D7D4F37BB989"
        //sha1
        //gov_cert_hex = "3082026D30820217A00302010202010B300D06092A864886F70D01010B05003075310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310B3009060355040A0C024341310C300A060355040B0C03565542310B300906035504030C0243413118301606092A864886F70D01090116096361407675622E6265301E170D3137303531373036323335395A170D3230303231313036323335395A304F310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310C300A060355040A0C03565542310C300A06035504030C03474F56305C300D06092A864886F70D0101010500034B003048024100C7A1D94ECD0C38D479C419EE1A017B13E05A9CC27BB2AEBAEA6F3B5E4D6D8974E4A73C4F4A7F2C6B52222F72EDB3F49C634F6CFCAD16E11B66B65AE869F45E4B0203010001A381B73081B4301D0603551D0E04160414402A635607C77E36458D6C9D944A2D419FF0B02F301F0603551D2304183016801435245A6A2549527B9DF54AC1288D39C77B00405030090603551D1304023000300B0603551D0F0404030205A0302C0603551D110425302382096C6F63616C686F737487047F000001871000000000000000000000000000000001302C06096086480186F842010D041F161D4F70656E53534C2047656E657261746564204365727469666963617465300D06092A864886F70D01010B0500034100824EFF9C2F07473BBF439BBDD427AAA92D56BD96A9FF7EEEB390F4D6EA82286B49828DB98785B16858B68AF560AAF9DF89B6733616F4FEDB2FBD3554788B9B54";
        //new sha1 certificate
        gov_cert_hex = "3082026D30820217A003020102020101300D06092A864886F70D01010505003075310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310B3009060355040A0C024341310C300A060355040B0C03565542310B300906035504030C0243413118301606092A864886F70D01090116096361407675622E6265301E170D3137303531383133303030345A170D3230303231323133303030345A304F310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310C300A060355040A0C03565542310C300A06035504030C03474F56305C300D06092A864886F70D0101010500034B003048024100D68699657BF8EE12399D3A24A477CD094A27DDD51B8C99CEFD15C17D2FBE42676C95FFD6BF9402E3E06C55DBB50B3504CBE26D6AC9D7E9AEA57D206673EFE9470203010001A381B73081B4301D0603551D0E041604142A8DEF92A80464783437CD2FA6AB256393613459301F0603551D230418301680140082A0BEDC088FD044D1FE31A0272DC006C49D6B30090603551D1304023000300B0603551D0F0404030205A0302C0603551D110425302382096C6F63616C686F737487047F000001871000000000000000000000000000000001302C06096086480186F842010D041F161D4F70656E53534C2047656E657261746564204365727469666963617465300D06092A864886F70D01010505000341005C61644A6FEBCCC3AB5260FA213DB43F8ED8A517375EBBF177B6DC9957213F87DF3FB3831211E77BFC2355C2DCC3358B9D326D426EB597DB22B57A4555FAF2C1";        
        gov_cert_bytes = hexStringToByteArray(gov_cert_hex);

        int temp_int = arraySubstrIndex(gov_cert_bytes, MODULUS_BYTES) + MODULUS_BYTES.length;
        gov_modulus_bytes = new byte[LENGTH_RSA_512_BYTES];
        Util.arrayCopy(gov_cert_bytes, (short) temp_int, gov_modulus_bytes, offset_0, (short) LENGTH_RSA_512_BYTES);
        gov_exp_pub_bytes = hexStringToByteArray("010001");

        // ca certificates
        
        //ca
        ca_cert_hex = "30820243308201EDA00302010202090080F938B672EFAF2E300D06092A864886F70D01010505003075310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310B3009060355040A0C024341310C300A060355040B0C03565542310B300906035504030C0243413118301606092A864886F70D01090116096361407675622E6265301E170D3137303531383132353635385A170D3137303631373132353635385A3075310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310B3009060355040A0C024341310C300A060355040B0C03565542310B300906035504030C0243413118301606092A864886F70D01090116096361407675622E6265305C300D06092A864886F70D0101010500034B003048024100F737CE4E93501A036FFCA0D14AAC932AECE3B8AF17A48FF7BF3FD93B98DA70B2DC950625CE54EDB7DB31C58D7B9A3100BCD13086DFAADE1A122B2FBD4DD5499D0203010001A360305E301D0603551D0E041604140082A0BEDC088FD044D1FE31A0272DC006C49D6B301F0603551D230418301680140082A0BEDC088FD044D1FE31A0272DC006C49D6B300F0603551D130101FF040530030101FF300B0603551D0F040403020106300D06092A864886F70D0101050500034100009860DAF3C2C8E78390077C9EFAB76E3B23C1CC79D9FECC8BEC03FAAC5C7F351EF37A6F554DFAAE918882485D9E0C47AAD2852DCF528163A69A6B43E1AF7818";
        ca_cert_bytes = hexStringToByteArray(ca_cert_hex);
        
//        temp_int = arraySubstrIndex(ca_cert_bytes, MODULUS_BYTES) + MODULUS_BYTES.length;
//        ca_modulus_bytes = new byte[LENGTH_RSA_512_BYTES];
//        Util.arrayCopy(ca_cert_bytes, (short) temp_int, ca_modulus_bytes, offset_0, (short) LENGTH_RSA_512_BYTES);
//        ca_exp_pub_bytes = hexStringToByteArray("010001");
        
        //common certificates
        //common private key
        //encrypted pkcs8
        //common_key_hex = "308201A6304006092A864886F70D01050D3033301B06092A864886F70D01050C300E04089D940421C0D8B82502020800301406082A864886F70D03070408B3DD6AC8E640AB7004820160DBDB427286AC7380A65C63B79EA7322FAE029161A01B181C3075BF2A94DBD103A472A6330911B2B59A76FB1E95E4D5E72E8E4393181221CD358DBEE67C69CCE2B5D592B781B4B86DADCD6BA190B19CC12681818EB8D03920B795A069481389A2507B483648916049DF455F1983694F4ECD7B7E5D564070CE2BF26E5645C11CB621EF19557D1E785C3D918C749C87FC87DF6F8868D4349C1925FA9F9A6DF90F08ABBB9D85F441B08EC9778E0B4CFAE476ED8A089B0ECC701AB36B141BB9F53B95BBEDEC29E048DF32D7F66922C86C83F9BB15B2083B01B9DFE833E5F8E71EF890A302C12E840E2DD99590C735F4B9CBF435E0E1DDAF8EE38F3FBB7DEDF30E6A8E5664691466EE598023CB9676F1C64CF6DD7C69B44DDBDE0E6D3527DB5DAB1216DC40872637308D14D1775DD24F68106AE2CF4991F8411BD9A3CB1E0EBE27A8CCE0CE5B77F2A56E9B2216E397143B0F0D33F64FDF04573D53288B6F6A98BD6A26";
        //pkcs8
        common_key_hex = "30820156020100300D06092A864886F70D0101010500048201403082013C020100024100C3112DBCA42C1E2936CDDDDCE69D69CA14E0D1DF8FDD3477F972AEF1C9F2F4EFD4B6E4F074FF88E797AF134ED55682C414D8BC941E2CEF9A876A64361FE4865D020301000102410089C5454759B06B30F2AB1DCA99FA8DB01364E1F602F6D9CAEE9C68210F60104B638752516675BF54E06D5715D93E5E734906F59A268E5BA89E8CC1AF4F2ED961022100E0E4DD3211DB93B7F9F2B34E30D0222C8A73D069BB2BBDBEB185B0166E015575022100DE0C312A2BC58E2264C07159EF264B41A28D0F99A8819C73C6280B537F098849022100D8623C95DD6AC901BE638FB44EF123C079629F87EBC85563F288AFF994D481B502206FE492EDDE4ADA1A08CD55116DCACD4790E3268656FCA15B51F2A1EA7C6CD049022100A875A78D59CCA14D7E05EDAF21D492E1243E2955A418D2C47D5FE0C507A7A1CE";
        //pkcs1
        //common_key_hex = "3082013C020100024100C3112DBCA42C1E2936CDDDDCE69D69CA14E0D1DF8FDD3477F972AEF1C9F2F4EFD4B6E4F074FF88E797AF134ED55682C414D8BC941E2CEF9A876A64361FE4865D020301000102410089C5454759B06B30F2AB1DCA99FA8DB01364E1F602F6D9CAEE9C68210F60104B638752516675BF54E06D5715D93E5E734906F59A268E5BA89E8CC1AF4F2ED961022100E0E4DD3211DB93B7F9F2B34E30D0222C8A73D069BB2BBDBEB185B0166E015575022100DE0C312A2BC58E2264C07159EF264B41A28D0F99A8819C73C6280B537F098849022100D8623C95DD6AC901BE638FB44EF123C079629F87EBC85563F288AFF994D481B502206FE492EDDE4ADA1A08CD55116DCACD4790E3268656FCA15B51F2A1EA7C6CD049022100A875A78D59CCA14D7E05EDAF21D492E1243E2955A418D2C47D5FE0C507A7A1CE";
        common_cert_hex = "3082028830820232A00302010202010A300D06092A864886F70D01010505003075310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310B3009060355040A0C024341310C300A060355040B0C03565542310B300906035504030C0243413118301606092A864886F70D01090116096361407675622E6265301E170D3137303531383133313435315A170D3230303231323133313435315A306A310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310C300A060355040A0C03565542310F300D06035504030C06434F4D4D4F4E31163014060A0992268993F22C64040D0C06636F6D6D6F6E305C300D06092A864886F70D0101010500034B003048024100C3112DBCA42C1E2936CDDDDCE69D69CA14E0D1DF8FDD3477F972AEF1C9F2F4EFD4B6E4F074FF88E797AF134ED55682C414D8BC941E2CEF9A876A64361FE4865D0203010001A381B73081B4301D0603551D0E041604147E14B56E263AD7B7A12823E69AE961A3FD4913F0301F0603551D230418301680140082A0BEDC088FD044D1FE31A0272DC006C49D6B30090603551D1304023000300B0603551D0F0404030205A0302C0603551D110425302382096C6F63616C686F737487047F000001871000000000000000000000000000000001302C06096086480186F842010D041F161D4F70656E53534C2047656E657261746564204365727469666963617465300D06092A864886F70D0101050500034100A28D3F7B004D69453B6E05F675D6D47BC932502B9F621FB04CAC322910D3EC6669E154764894559DACBC3BCE38B0139CF1C583D22AF245741AA854EF39D226E1";
        //test com certificate
        //common_key_hex = "30820155020100300D06092A864886F70D01010105000482013F3082013B020100024100B1CD5462294605137E6C307947FDE6870AB79B18B944C39D4831736811E826C9990A7F190AC1F44BAD4683DCF6FD98A9E211FA620EE7711B9DB61778664ED5D30203010001024066B8F1029143E1D4E45A4F1B12ABAECEE0333988EC28BD37162973BA71760549C656C1C19101B23487885215C7C3C6524C69C169E8B0D044AA47CB0D55F9E229022100E54EA535F912B3BA5D3C749F70C6CBA44E5CCF55583349A568ECB68023EF9DD7022100C67FD4C5F86C42B91205082234055CBCDCA3FD3440A957DE6B7ECCE0C014F065022064FD18F7C7453C5064859E9B25B0F7B8DA2637CDCF756F06E149F72A422962AB022100997F4A93589AA732243C1DE10D2744628BA08871FABAB947370B13F58CB3E47D022100B8C4736ACB7471945BCDBFCBBD468A982E7CA18C12EA09448DE5651590300A2E";
        //common_cert_hex = "308202823082022CA00302010202010B300D06092A864886F70D01010505003075310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310B3009060355040A0C024341310C300A060355040B0C03565542310B300906035504030C0243413118301606092A864886F70D01090116096361407675622E6265301E170D3137303533303039303634375A170D3230303232343039303634375A3064310B30090603550406130242453111300F06035504080C084272757373656C733111300F06035504070C084272757373656C73310C300A060355040A0C03565542310C300A06035504030C03434F4D31133011060A0992268993F22C64040D0C03636F6D305C300D06092A864886F70D0101010500034B003048024100B1CD5462294605137E6C307947FDE6870AB79B18B944C39D4831736811E826C9990A7F190AC1F44BAD4683DCF6FD98A9E211FA620EE7711B9DB61778664ED5D30203010001A381B73081B4301D0603551D0E0416041475AF0D7E551A4FBEEA2A20E0584D0AFAC4F38835301F0603551D230418301680140082A0BEDC088FD044D1FE31A0272DC006C49D6B30090603551D1304023000300B0603551D0F0404030205A0302C0603551D110425302382096C6F63616C686F737487047F000001871000000000000000000000000000000001302C06096086480186F842010D041F161D4F70656E53534C2047656E657261746564204365727469666963617465300D06092A864886F70D0101050500034100C554945CA9400631940B339BDAC555B0168BFCD3EB3EAAC9D11D931F1FE0863252C2C7AB068A2D21D6A0265E4950763C2751D28E66EFF4DE62C46335725F0953";
                
        common_key_bytes = hexStringToByteArray(common_key_hex);
        common_cert_bytes = hexStringToByteArray(common_cert_hex);
        
//        String privKeyPEM = "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAwxEtvKQsHik2zd3c5p1pyhTg0d+P3TR3+XKu8cny9O/UtuTwdP+I55evE07VVoLEFNi8lB4s75qHamQ2H+SGXQIDAQABAkEAicVFR1mwazDyqx3KmfqNsBNk4fYC9tnK7pxoIQ9gEEtjh1JRZnW/VOBtVxXZPl5zSQb1miaOW6iejMGvTy7ZYQIhAODk3TIR25O3+fKzTjDQIiyKc9Bpuyu9vrGFsBZuAVV1AiEA3gwxKivFjiJkwHFZ7yZLQaKND5mogZxzxigLU38JiEkCIQDYYjyV3WrJAb5jj7RO8SPAeWKfh+vIVWPyiK/5lNSBtQIgb+SS7d5K2hoIzVURbcrNR5DjJoZW/KFbUfKh6nxs0EkCIQCodaeNWcyhTX4F7a8h1JLhJD4pVaQY0sR9X+DFB6ehzg==";
//
//        PrivateKey privKey;
//		try {
//			//KeyFactory keyFactory=KeyFactory.getInstance("RSA");
//			java.security.PrivateKey priv=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(common_key_bytes));
//			byte [] encoded = Base64.decode(privKeyPEM);
//			//byte [] pkcs8EncodedBytes = Base64.decode(pkcs8Pem, Base64.DEFAULT);
//			// PKCS8 decode the encoded RSA private key
//	        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
//			KeyFactory kf = KeyFactory.getInstance("RSA");
//			privKey = (PrivateKey) kf.generatePrivate(keySpec);
//			// Display the results
//	        System.out.println(privKey);
//		} catch (InvalidKeySpecException e) {
//			// TODO Auto-generated catch block
//			//e.printStackTrace();
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			//e.printStackTrace();
//		} catch (Base64DecodingException e) {
//			// TODO Auto-generated catch block
//			//e.printStackTrace();
//		}

        
//http://www.javased.com/?api=java.security.PrivateKey        
//        KeyFactory keyFactory;
//		try {
//			keyFactory = KeyFactory.getInstance("RSA");
//			java.security.PrivateKey priv=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(common_key_bytes));
//			//RSAPrivateKey test = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(common_key_bytes));
//			
//			// decode private key
//            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(common_key_bytes);
//            RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
//
//			
//			int i = 0;
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			//e.printStackTrace();
//		} catch (InvalidKeySpecException e) {
//			// TODO Auto-generated catch block
//			//e.printStackTrace();
//		}

//        
        temp_int = arraySubstrIndex(common_cert_bytes, MODULUS_BYTES) + MODULUS_BYTES.length;
        common_modulus_bytes = new byte[LENGTH_RSA_512_BYTES];
        Util.arrayCopy(common_cert_bytes, (short) temp_int, common_modulus_bytes, offset_0, (short) LENGTH_RSA_512_BYTES);

        temp_int = arraySubstrIndex(common_key_bytes, EXPONENT_BYTES) + EXPONENT_BYTES.length;
        common_exp_priv_bytes = new byte[LENGTH_RSA_512_BYTES];
        Util.arrayCopy(common_key_bytes, (short) temp_int, common_exp_priv_bytes, offset_0, (short) LENGTH_RSA_512_BYTES);
        //common_exp_pub_bytes = hexStringToByteArray("010001");

        // make keys
        gov_pk.setExponent(gov_exp_pub_bytes, offset_0, (short) gov_exp_pub_bytes.length);
        gov_pk.setModulus(gov_modulus_bytes, offset_0, (short) gov_modulus_bytes.length);

        //ca_pk.setExponent(ca_exp_pub_bytes, offset_0, (short) ca_exp_pub_bytes.length);
        //ca_pk.setModulus(ca_modulus_bytes, offset_0, (short) ca_modulus_bytes.length);
        
        common_sk.setExponent(common_exp_priv_bytes, offset_0, (short) common_exp_priv_bytes.length);
        common_sk.setModulus(common_modulus_bytes, offset_0, (short) common_modulus_bytes.length);
        //common_pk.setExponent(common_exp_pub_bytes, offset_0, (short) common_exp_pub_bytes.length);
        //common_pk.setModulus(common_modulus_bytes, offset_0, (short) common_modulus_bytes.length);
		
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
        register();
    }

    /*
     * This method is called by the JCRE when installing the applet on the card.
     */
    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        new IdentityCard();
    }

    /*
     * If no tries are remaining, the applet refuses selection. The card can,
     * therefore, no longer be used for identification.
     */
    public boolean select() {
        if (pin.getTriesRemaining() == 0)
            return false;
        return true;
    }

    /*
     * This method is called when the applet is selected and an APDU arrives.
     */
    // it is always waiting on requests
    // you can not use new
    // you can only use static!!!
    public void process(APDU apdu) throws ISOException {
        System.out.println("process");

        // A reference to the buffer, where the APDU data is stored, is
        // retrieved.
        byte[] buffer = apdu.getBuffer();

        // If the APDU selects the applet, no further processing is required.
        if (this.selectingApplet())
            return;

        // Check whether the indicated class of instructions is compatible with
        // this applet.
        if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        // A switch statement is used to select a method depending on the
        // instruction
        switch (buffer[ISO7816.OFFSET_INS]) {
            case VALIDATE_PIN_INS:
                validatePIN(apdu);
                break;
            case GET_SERIAL_INS:
                getSerial(apdu);
                break;

            // step 1
            case HELLO_DIS:
                validateHello(apdu);
                break;
            case NEW_TIME:
                newTime(apdu);
                break;

            // step 2
            case NEW_SERVICE_CERT:
                newServiceCertificate(apdu);
                break;
            case SERVICE_CERT_DONE:
                treatServiceCertificate(apdu);
                break;
            case SERVICE_AUTH:
                authenticateService(apdu);
                break;
            //step 2 + 3
            case SERVICE_RESP_CHALLENGE:
                verifyServiceRespChallenge(apdu);
                break;

            // step 3
            case SERVICE_CHALLENGE:
                sendServiceChallengeResponse(apdu);
                break;

            // step 4
            case NEW_QUERY:
                newQuery(apdu);
                break;
            case QUERY_DONE:
                treatQuery(apdu);
                break;
            //case VALIDATE_PIN_INS - already defined
            case GET_QUERY:
                if (isServiceAuthenticated && isPinValidated) {
                    getQuery(apdu);
                } else {
                    ISOException.throwIt(SW_ABORT);
                }
                break;

            // If no matching instructions are found it is indicated in the status
            // word of the response.
            // given that indicates
            // the type of warning. There are several predefined warnings in the
            // 'ISO7816' class.
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /*
     * This method is used to authenticate the owner of the card using a PIN
     * code.
     */
    private void validatePIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // The input data needs to be of length 'PIN_SIZE'.
        // Note that the byte values in the Lc and Le fields represent values
        // between
        // 0 and 255. Therefore, if a short representation is required, the
        // following
        // code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC]
        // & 0x00FF);
        if (buffer[ISO7816.OFFSET_LC] == PIN_SIZE) {
            // This method is used to copy the incoming data in the APDU buffer.
            apdu.setIncomingAndReceive();
            // Note that the incoming APDU data size may be bigger than the APDU
            // buffer
            // size and may, therefore, need to be read in portions by the
            // applet.
            // Most recent smart cards, however, have buffers that can contain
            // the maximum
            // data size. This can be found in the smart card specifications.
            // If the buffer is not large enough, the following method can be
            // used:
            //
            // byte[] buffer = apdu.getBuffer();
            // short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
            // Util.arrayCopy(buffer, START, storage, START, (short)5);
            // short readCount = apdu.setIncomingAndReceive();
            // short i = ISO7816.OFFSET_CDATA;
            // while ( bytesLeft > 0){
            // Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i,
            // readCount);
            // bytesLeft -= readCount;
            // i+=readCount;
            // readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
            // }
            if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE)) {
                ISOException.throwIt(SW_VERIFICATION_FAILED);
            } else {
                isPinValidated = true;
            }
        } else
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    /*
     * This method checks whether the user is authenticated and sends the
     * identity file.
     */
    private void getSerial(APDU apdu) {
        // If the pin is not validated, a response APDU with the
        // 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
        if (!pin.isValidated())
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else {
            // This sequence of three methods sends the data contained in
            // 'identityFile' with offset '0' and length 'identityFile.length'
            // to the host application.
            apdu.setOutgoing(); // you can not allocate memory, you must used
            // your input, it clears your APDU
            apdu.setOutgoingLength((short) serial.length); // 0 if you don't
            // want to send
            // something, the
            // lenght of the
            // data
            apdu.sendBytesLong(serial, // array that you want to send
                    offset_0, // offset
                    (short) serial.length); // if you want to send more data!!
            // you must send the data in chunks!
            // If error <-- smaller chunks
        }
    }

    // STEP 1 ---------------------------------------------------------------------------------
    // (2)
    private void validateHello(APDU apdu) {
        System.out.println("validateHello");

        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        //step 1 (3)
        if (!checkTimestamp(buffer, (int) ISO7816.OFFSET_CDATA, (int) buffer[ISO7816.OFFSET_LC]))
            ISOException.throwIt(SW_REQ_REVALIDATION);
    }

    private boolean checkTimestamp(byte[] buffer, int offset, int length) {
        byte[] tempArray = new byte[(short) length];
        Util.arrayCopy(buffer, (short) offset, tempArray, offset_0, (short) length);

        long bufferTime = byteArrayToLong(tempArray);
        long lastTime = byteArrayToLong(lastValidationTime);

        System.out.println(bufferTime);
        System.out.println(lastTime);

        return ((bufferTime - lastTime) < VALIDATION_TIME);
    }

    private long byteArrayToLong(byte[] byteArray) {
        return Long.parseLong(byteArrayToHexString(byteArray), 16);
    }

    // (9)
    private void newTime(APDU apdu) {
        System.out.println("newTime");
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        byte[] newTime = new byte[buffer[ISO7816.OFFSET_CDATA]
                + buffer[ISO7816.OFFSET_CDATA + buffer[ISO7816.OFFSET_CDATA] + 1]];
        byte[] newTimestamp = new byte[buffer[ISO7816.OFFSET_CDATA]];
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), newTime, offset_0, (short) newTimestamp.length);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), newTimestamp, offset_0,
                (short) newTimestamp.length);
        byte[] newTimestring = new byte[buffer[ISO7816.OFFSET_CDATA + newTimestamp.length + 1]];

        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + newTimestamp.length + 2), newTime,
                (short) newTimestamp.length, (short) newTimestring.length);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + newTimestamp.length + 2), newTimestring, offset_0,
                (short) newTimestring.length);
        byte[] newTimeSig = new byte[buffer[ISO7816.OFFSET_CDATA + newTime.length + 2]];

        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + newTime.length + 2 + 1), newTimeSig, offset_0,
                (short) newTimeSig.length);

        // (10) Verify signature with PK of Government
        System.out.println("Verify signature with PK of Government");
        //why not ALG_RSA_SHA_256_PKCS1
        //https://docs.oracle.com/javacard/3.0.5/api/javacard/security/Signature.html
        //https://www.win.tue.nl/pinpasjc/docs/apis/jc222/javacard/security/Signature.html
        //Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1, false); --> not yet in 2.2.2
        //Signature sig = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        //sha1
        Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        sig.init(gov_pk, Signature.MODE_VERIFY);
        System.out.println("verify test");
        Boolean verify = sig.verify(newTime, offset_0, (short) newTime.length, newTimeSig, offset_0,
                (short) newTimeSig.length);

        if (verify) {
            System.out.println("Time signature verified");
            // (11) Abort if current time on card is later than the time from the Government Timeserver
            if (byteArrayToLong(lastValidationTime) < byteArrayToLong(newTimestamp)) {

                // (12) Update the time.
                lastValidationTime = new byte[newTimestamp.length];
                Util.arrayCopy(newTimestamp, offset_0, lastValidationTime, offset_0, (short) newTimestamp.length);
                lastValidationTimeString = new byte[newTimestring.length];
                Util.arrayCopy(newTimestring, offset_0, lastValidationTimeString, offset_0,
                        (short) newTimestring.length);

            } else
                ISOException.throwIt(SW_ABORT);
        } else
            ISOException.throwIt(SW_ABORT);
    }

    // STEP 2 --------------------------------------------------------------------------------
    // step 2 (1)
    private void newServiceCertificate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        int bufferLength;
        if (buffer[ISO7816.OFFSET_LC] < 0) {
            bufferLength = buffer[ISO7816.OFFSET_LC] * -1;
        } else {
            bufferLength = buffer[ISO7816.OFFSET_LC];
        }
        byte[] temp = new byte[lastCert.length];
        Util.arrayCopy(lastCert, offset_0, temp, offset_0, (short) temp.length);
        lastCert = new byte[temp.length + bufferLength];
        Util.arrayCopy(temp, offset_0, lastCert, offset_0, (short) temp.length);
        Util.arrayCopy(buffer, (short) 5, lastCert, (short) temp.length, (short) bufferLength);
        System.out.println(byteArrayToHexString(lastCert));
    }

    private void treatServiceCertificate(APDU apdu) {
        //get issuer cn
        int issuerOffset = arraySubstrIndex(lastCert, CN_BYTES) + CN_BYTES.length;
        lastCertIssuer = new byte[lastCert[issuerOffset]];
        Util.arrayCopy(lastCert, (short) (issuerOffset + 1), lastCertIssuer, offset_0, (short) lastCertIssuer.length);
        //get issuer domain
        int issuerDomainOffset = arraySubstrIndexFrom(lastCert, DOMAIN_BYTES, issuerOffset) + DOMAIN_BYTES.length;
        last_cert_issuer_domain = new byte[lastCert[issuerDomainOffset]];
        Util.arrayCopy(lastCert, (short) (issuerDomainOffset + 1), last_cert_issuer_domain, offset_0, (short) last_cert_issuer_domain.length);
        //get valid after
        int validAfterOffset = arraySubstrIndexFrom(lastCert, VALIDITY_BYTES, issuerDomainOffset) + VALIDITY_BYTES.length;
        last_cert_valid_after = new byte[12];
        Util.arrayCopy(lastCert, (short) validAfterOffset, last_cert_valid_after, offset_0, (short) last_cert_valid_after.length);
        //get valid before
        int validBeforeOffset = arraySubstrIndexFrom(lastCert, VALIDITY_BYTES, validAfterOffset) + VALIDITY_BYTES.length;
        last_cert_valid_before = new byte[12];
        Util.arrayCopy(lastCert, (short) validBeforeOffset, last_cert_valid_before, offset_0, (short) last_cert_valid_before.length);
        //get subject cn
        int subjectOffset = arraySubstrIndexFrom(lastCert, CN_BYTES, validBeforeOffset) + CN_BYTES.length;
        last_cert_subject_cn = new byte[lastCert[subjectOffset]];
        Util.arrayCopy(lastCert, (short) (subjectOffset + 1), last_cert_subject_cn, offset_0, (short) last_cert_subject_cn.length);
        //get subject domain
        int subjectDomainOffset = arraySubstrIndexFrom(lastCert, DOMAIN_BYTES, subjectOffset) + DOMAIN_BYTES.length;
        last_cert_subject_domain = new byte[lastCert[subjectDomainOffset]];
        Util.arrayCopy(lastCert, (short) (subjectDomainOffset + 1), last_cert_subject_domain, offset_0, (short) last_cert_subject_domain.length);
        //get pk modulus
        int modulus_offset = arraySubstrIndexFrom(lastCert, MODULUS_BYTES, subjectDomainOffset) + MODULUS_BYTES.length;
        last_cert_modulus = new byte[LENGTH_RSA_512_BYTES];
        Util.arrayCopy(lastCert, (short) (modulus_offset), last_cert_modulus, offset_0, (short) last_cert_modulus.length);
        //get pk exponent
        int exponentOffset = modulus_offset + last_cert_modulus.length + 1;
        last_cert_exponent = new byte[lastCert[exponentOffset]];
        Util.arrayCopy(lastCert, (short) (exponentOffset + 1), last_cert_exponent, offset_0, (short) last_cert_exponent.length);
        //get signature
        int signatureOffset = arraySubstrIndexFrom(lastCert, SIGNATURE_BYTES, exponentOffset) + SIGNATURE_BYTES.length;
        last_cert_signature = new byte[LENGTH_RSA_512_BYTES];
        last_cert_tbs = new byte[signatureOffset - SIGNATURE_BYTES.length - 4];
        Util.arrayCopy(lastCert, (short) (signatureOffset), last_cert_signature, offset_0, (short) last_cert_signature.length);
        Util.arrayCopy(lastCert, (short) 4, last_cert_tbs, offset_0, (short) last_cert_tbs.length);

        //verify
        System.out.println("verify last cert");
        System.out.println("lastCertIssuer: " + byteArrayToHexString(lastCertIssuer));
        System.out.println("last_cert_issuer_domain: " + byteArrayToHexString(last_cert_issuer_domain));
        System.out.println("last_cert_valid_after: " + byteArrayToHexString(last_cert_valid_after));
        System.out.println("last_cert_valid_before: " + byteArrayToHexString(last_cert_valid_before));
        System.out.println("last_cert_modulus: " + byteArrayToHexString(last_cert_modulus));
        System.out.println("last_cert_exponent: " + byteArrayToHexString(last_cert_exponent));
        System.out.println("last_cert_signature: " + byteArrayToHexString(last_cert_signature));
    }

    private void authenticateService(APDU apdu) {
        //Step 2 (2) verify certificate

        //check if the service provider certificate is signed by the root CA?
		try {
			if (verifyCert()){
				System.out.println("Certificate verified");
			}else ISOException.throwIt(SW_SIG_NO_MATCH);
		} catch (InvalidKeyException e) {
			ISOException.throwIt(SW_SIG_NO_MATCH);
		} catch (CertificateException e) {
			ISOException.throwIt(SW_SIG_NO_MATCH);
		} catch (NoSuchAlgorithmException e) {
			ISOException.throwIt(SW_SIG_NO_MATCH);
		} catch (NoSuchProviderException e) {
			ISOException.throwIt(SW_SIG_NO_MATCH);
		} catch (SignatureException e) {
			ISOException.throwIt(SW_SIG_NO_MATCH);
		}

        //Step 2 (3) verify if certificate is valid
        if (verifyValid(last_cert_valid_after, last_cert_valid_before, lastValidationTimeString)) {
            System.out.println("Certificate valid");
        } else ISOException.throwIt(SW_CERT_EXPIRED);

        //Step 2 (4) generate new symmetric key
        last_symm_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        genSymmKey();
        last_symm_key.setKey(last_symm_key_bytes, offset_0);

        //Step 2 (5) asymetrische encryptie with public key of service provider
        last_cert_pk = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        last_cert_pk.setExponent(last_cert_exponent, offset_0, (short) last_cert_exponent.length);
        last_cert_pk.setModulus(last_cert_modulus, offset_0, (short) last_cert_modulus.length);
        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        cipher.init(last_cert_pk, Cipher.MODE_ENCRYPT);
        last_symm_key_encrypted = new byte[LENGTH_RSA_512_BYTES];
        cipher.doFinal(last_symm_key_bytes, offset_0, (short) last_symm_key_bytes.length, last_symm_key_encrypted, offset_0);

        //generate challenge
        genChallenge();

        //encrypt challenge with generated symmetric key
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(last_symm_key, Cipher.MODE_ENCRYPT);
        int i = last_challenge.length + last_cert_subject_cn.length + 2;
        i += LENGTH_AES_128_BYTES - (i % 16);
        last_challenge_with_subject = new byte[i];
        last_challenge_with_subject[0] = (byte) last_challenge.length;
        Util.arrayCopy(last_challenge, offset_0, last_challenge_with_subject, offset_1, (short) last_challenge.length);
        last_challenge_with_subject[last_challenge.length + 1] = (byte) last_cert_subject_cn.length;
        Util.arrayCopy(last_cert_subject_cn, offset_0, last_challenge_with_subject, (short) (last_challenge.length + 2), (short) last_cert_subject_cn.length);
        last_challenge_with_subject_encrypted = new byte[i];
        cipher.doFinal(last_challenge_with_subject, offset_0, (short) last_challenge_with_subject.length, last_challenge_with_subject_encrypted, offset_0);

        System.out.println("sending this challenge: " + byteArrayToHexString(last_challenge));
        System.out.println("sending this subject: " + byteArrayToHexString(last_challenge_with_subject));
        System.out.println("sending this symm key: " + byteArrayToHexString(last_symm_key_bytes));

        //generate the response array with the symmetric key and the challenge
        // length + symm key + length + challenge with subject
        serviceAuthResponse = new byte[1 + last_symm_key_encrypted.length + 1 + last_challenge_with_subject_encrypted.length];
        serviceAuthResponse[0] = (byte) last_symm_key_encrypted.length;
        Util.arrayCopy(last_symm_key_encrypted, offset_0, serviceAuthResponse, offset_1, (short) last_symm_key_encrypted.length);
        serviceAuthResponse[last_symm_key_encrypted.length + 1] = (byte) last_challenge_with_subject_encrypted.length;
        Util.arrayCopy(last_challenge_with_subject_encrypted, offset_0, serviceAuthResponse, (short) (last_symm_key_encrypted.length + 2), (short) last_challenge_with_subject_encrypted.length);

        //send response back to M
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) serviceAuthResponse.length);
        System.out.println("sending response with length " + serviceAuthResponse.length);
        apdu.sendBytesLong(serviceAuthResponse, offset_0, (short) serviceAuthResponse.length);

    }

    private boolean verifyCert() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    	System.out.println("verifying certificate");
        
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(lastCert);
        X509Certificate cert_SP = (X509Certificate)certFactory.generateCertificate(in);
        
        CertificateFactory certFactoryCA = CertificateFactory.getInstance("X.509");
        InputStream inCA = new ByteArrayInputStream(ca_cert_bytes);
        X509Certificate cert_CA = (X509Certificate)certFactoryCA.generateCertificate(inCA);
        
        try
        {   //Not your CA's. Check if it has been signed by your CA
        	java.security.PublicKey pubKeyCA = cert_CA.getPublicKey();
        	
        	//cert_CA.verify(pubKeyCA);
        	cert_SP.verify(pubKeyCA);
        	
        	return true;
        }
        catch(Exception e){   
            //throw new CertificateException("Certificate not trusted",e);
        	return false;
        }
    }

    private boolean verifyValid(byte[] cert_after, byte[] cert_before, byte[] time_string) {
        System.out.println("before: " + byteArrayToHexString(cert_before));
        System.out.println("after: " + byteArrayToHexString(cert_after));
        System.out.println("time: " + byteArrayToHexString(time_string));

        String before = byteArrayToHexString(cert_before);
        String after = byteArrayToHexString(cert_after);
        String time = byteArrayToHexString(time_string);

        return (time.compareTo(after) < 0 && time.compareTo(before) > 0);
    }

    private void genSymmKey() {
        last_symm_key_bytes = new byte[LENGTH_AES_128_BYTES];
        // ALG_SECURE_RANDOM is not implemented in the simulator... See http://stackoverflow.com/questions/29898209/using-java-card-s-randondata-getinstance
        srng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        srng.generateData(last_symm_key_bytes, offset_0, (short) last_symm_key_bytes.length);
    }

    private void genChallenge() {
        last_challenge = new byte[2];
        srng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        srng.generateData(last_challenge, offset_0, offset_2);
    }

    // Step 2 (13)
    private void verifyServiceRespChallenge(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        System.out.println("using key to decrypt: " + byteArrayToHexString(last_symm_key_bytes));

        byte[] messageChunk = new byte[buffer[ISO7816.OFFSET_LC]];
        Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, messageChunk, offset_0, (short) messageChunk.length);
        System.out.println("incoming buffer: " + byteArrayToHexString(messageChunk));
        System.out.println("incoming buffer length: " + messageChunk.length);

        last_challenge_response_aes = new byte[LENGTH_AES_128_BYTES];
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(last_symm_key, Cipher.MODE_DECRYPT);
        cipher.doFinal(messageChunk, offset_0, (short) messageChunk.length, last_challenge_response_aes, offset_0);
        last_challenge_response = new byte[last_challenge_response_aes[0]];
        System.out.println(byteArrayToHexString(last_challenge_response_aes));
        System.out.println(last_challenge_response.length);
        Util.arrayCopy(last_challenge_response_aes, offset_1, last_challenge_response, offset_0, (short) last_challenge_response.length);

        chall_long = Long.parseLong(byteArrayToHexString(last_challenge), 16);
        chall_resp_long = Long.parseLong(byteArrayToHexString(last_challenge_response), 16);

        if ((chall_resp_long - chall_long) == 1) {
            isServiceAuthenticated = true;
            System.out.println("Server authenticated!");
            //challenge answer OK, SP is now authenticated
            //respond to challenge from server
            last_server_challenge = new byte[last_challenge_response_aes[1 + last_challenge_response.length]];
            Util.arrayCopy(last_challenge_response_aes, (short) (1 + last_challenge_response.length + 1), last_server_challenge, offset_0, (short) last_server_challenge.length);

            //sign challenge with common SK - step 3 (6)
            int i = 1 + LENGTH_RSA_512_BYTES + 1 + common_cert_bytes.length;
            i += LENGTH_AES_128_BYTES - (i % 16);
            last_server_challenge_resp = new byte[i];
            last_server_challenge_resp[0] = (byte) LENGTH_RSA_512_BYTES;
            
            System.out.println("Signing challenge from service provider: " + byteArrayToHexString(last_server_challenge));
            
            //https://msec.be/wiscy/seminarie/ho_sc.pdf
            Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            sig.init(common_sk, Signature.MODE_SIGN);
            //short sigLength = sig.sign(last_server_challenge, offset, (short) last_server_challenge.length, last_server_challenge_resp, offset_1);
            short sigLength = sig.sign(last_server_challenge, offset_0, (short) (last_server_challenge.length), last_server_challenge_resp, offset_1);
            
            //add the common certificate - step 3 (7)
            System.out.println("cert length " + common_cert_bytes.length);
            last_server_challenge_resp[1 + LENGTH_RSA_512_BYTES] = (byte) (last_server_challenge_resp.length - 1 - LENGTH_RSA_512_BYTES - 1 - common_cert_bytes.length); //we will not send the cert length, but the number of remaining bytes in the array
            Util.arrayCopy(common_cert_bytes, offset_0, last_server_challenge_resp, (short) (1 + LENGTH_RSA_512_BYTES + 1), (short) common_cert_bytes.length);
            //encrypt with symmetric key - step 3 (7)
            cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            cipher.init(last_symm_key, Cipher.MODE_ENCRYPT);
            last_server_challenge_resp_encrypted = new byte[i];
            cipher.doFinal(last_server_challenge_resp, offset_0, (short) last_server_challenge_resp.length, last_server_challenge_resp_encrypted, offset_0);

            System.out.println("response to server: " + byteArrayToHexString(last_server_challenge_resp));
            //now wait for middleware to get the string as it is too long to send back in one response

        } else {
            ISOException.throwIt(SW_ABORT);
        }

    }


    // STEP 3 ----
    private void sendServiceChallengeResponse(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short i = (short) buffer[ISO7816.OFFSET_CDATA];
        if (i <= last_server_challenge_resp_encrypted.length / APDU_MAX_BUFF_SIZE) {
            int msgChunkLength = APDU_MAX_BUFF_SIZE;
            if (last_server_challenge_resp_encrypted.length - (i * APDU_MAX_BUFF_SIZE) < APDU_MAX_BUFF_SIZE) {
                msgChunkLength = last_server_challenge_resp_encrypted.length - (i * APDU_MAX_BUFF_SIZE);
            }
            if (msgChunkLength > 0) {
                byte[] msgChunk = new byte[msgChunkLength];
                System.arraycopy(last_server_challenge_resp_encrypted, APDU_MAX_BUFF_SIZE * i, msgChunk, 0, msgChunkLength);
                System.out.println(byteArrayToHexString(msgChunk));
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) msgChunkLength);
                System.out.println("sending response with length " + msgChunkLength);
                apdu.sendBytesLong(msgChunk, offset_0, (short) msgChunkLength);
            }
        } else {
            apdu.setOutgoing();
            apdu.setOutgoingLength(offset_0);
            apdu.sendBytesLong(new byte[0], offset_0, offset_0);
        }
    }


    // STEP 4 ----
    private void newQuery(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        int bufferLength;
        if (buffer[ISO7816.OFFSET_LC] < 0) {
            bufferLength = buffer[ISO7816.OFFSET_LC] * -1;
        } else {
            bufferLength = buffer[ISO7816.OFFSET_LC];
        }
        byte[] temp = new byte[last_query.length];
        Util.arrayCopy(last_query, offset_0, temp, offset_0, (short) temp.length);
        last_query = new byte[temp.length + bufferLength];
        Util.arrayCopy(temp, offset_0, last_query, offset_0, (short) temp.length);
        Util.arrayCopy(buffer, (short) 5, last_query, (short) temp.length, (short) bufferLength);
        System.out.println(byteArrayToHexString(last_query));
    }

    private void treatQuery(APDU apdu) {
        int i = 0;
        queryResult = new byte[offset_0];
        while (i < last_query.length) {
            queryItem = new byte[(short) last_query[i]];
            Util.arrayCopy(last_query, (short) (i + 1), queryItem, offset_0, (short) queryItem.length);

            if ("nym".getBytes().length == queryItem.length && (short) Util.arrayCompare(queryItem, offset_0, "nym".getBytes(), offset_0, (short) queryItem.length) == 0) {
                System.out.println("requested nym");
                if (!checkAuthorized(NYM_IDX, "nym".getBytes(), genNym())) {
                    ISOException.throwIt(SW_ABORT);
                    break;
                }
            } else if ("name".getBytes().length == queryItem.length && (short) Util.arrayCompare(queryItem, offset_0, "name".getBytes(), offset_0, (short) queryItem.length) == 0) {
                System.out.println("requested name");
                if (!checkAuthorized(NAME_IDX, "name".getBytes(), NAME)) {
                    ISOException.throwIt(SW_ABORT);
                    break;
                }
            } else if ("address".getBytes().length == queryItem.length && (short) Util.arrayCompare(queryItem, offset_0, "address".getBytes(), offset_0, (short) queryItem.length) == 0) {
                System.out.println("requested address");
                if (!checkAuthorized(ADDRESS_IDX, "address".getBytes(), ADDRESS)) {
                    ISOException.throwIt(SW_ABORT);
                    break;
                }
            } else if ("country".getBytes().length == queryItem.length && (short) Util.arrayCompare(queryItem, offset_0, "country".getBytes(), offset_0, (short) queryItem.length) == 0) {
                System.out.println("requested country");
                if (!checkAuthorized(COUNTRY_IDX, "country".getBytes(), COUNTRY)) {
                    ISOException.throwIt(SW_ABORT);
                    break;
                }
            } else if ("birthdate".getBytes().length == queryItem.length && (short) Util.arrayCompare(queryItem, offset_0, "birthdate".getBytes(), offset_0, (short) queryItem.length) == 0) {
                System.out.println("requested birthdate");
                if (!checkAuthorized(BIRTHDATE_IDX, "birthdate".getBytes(), BIRTHDATE)) {
                    ISOException.throwIt(SW_ABORT);
                    break;
                }
            } else if ("age".getBytes().length == queryItem.length && (short) Util.arrayCompare(queryItem, offset_0, "age".getBytes(), offset_0, (short) queryItem.length) == 0) {
                System.out.println("requested age");
                if (!checkAuthorized(AGE_IDX, "age".getBytes(), AGE)) {
                    ISOException.throwIt(SW_ABORT);
                    break;
                }
            } else if ("gender".getBytes().length == queryItem.length && (short) Util.arrayCompare(queryItem, offset_0, "gender".getBytes(), offset_0, (short) queryItem.length) == 0) {
                System.out.println("requested gender");
                if (!checkAuthorized(GENDER_IDX, "gender".getBytes(), GENDER)) {
                    ISOException.throwIt(SW_ABORT);
                    break;
                }
            } else if ("picture".getBytes().length == queryItem.length && (short) Util.arrayCompare(queryItem, offset_0, "picture".getBytes(), offset_0, (short) queryItem.length) == 0) {
                System.out.println("requested picture");
                if (!checkAuthorized(PICTURE_IDX, "picture".getBytes(), PICTURE)) {
                    ISOException.throwIt(SW_ABORT);
                    break;
                }
            }


            i++;
            i += queryItem.length;
        }
        System.out.println("loop done");

        //encrypt the query result
        i = queryResult.length;
        i += LENGTH_AES_128_BYTES - (i % 16);
        byte[] queryResultAES = new byte[i];
        Util.arrayCopy(queryResult, offset_0, queryResultAES, (short) (0), (short) queryResult.length);
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(last_symm_key, Cipher.MODE_ENCRYPT);
        query_result_encrypted = new byte[i];
        cipher.doFinal(queryResultAES, offset_0, (short) queryResultAES.length, query_result_encrypted, offset_0);

    }

    private boolean checkAuthorized(byte idx, byte[] param, byte[] val) {
        hasCheckAuthContent = false;
        if (DOMAIN_DEFAULT_BYTES.length == last_cert_subject_domain.length && (short) Util.arrayCompare(DOMAIN_DEFAULT_BYTES, offset_0, last_cert_subject_domain, offset_0, (short) last_cert_subject_domain.length) == 0) {
            System.out.println("default domain");
            if ((short) DOMAIN_DEFAULT_AUTH[(short) idx] == offset_1) {
                hasCheckAuthContent = true;
            }
        } else if (DOMAIN_EGOV_BYTES.length == last_cert_subject_domain.length && (short) Util.arrayCompare(DOMAIN_EGOV_BYTES, offset_0, last_cert_subject_domain, offset_0, (short) last_cert_subject_domain.length) == 0) {
            System.out.println("egov domain");
            if ((short) DOMAIN_EGOV_AUTH[(short) idx] == offset_1) {
                hasCheckAuthContent = true;
            }
        } else if (DOMAIN_SOCNET_BYTES.length == last_cert_subject_domain.length && (short) Util.arrayCompare(DOMAIN_SOCNET_BYTES, offset_0, last_cert_subject_domain, offset_0, (short) last_cert_subject_domain.length) == 0) {
            System.out.println("socnet domain");
            if ((short) DOMAIN_SOCNET_AUTH[(short) idx] == offset_1) {
                hasCheckAuthContent = true;
            }
        } else if (DOMAIN_SUPERMARKET_BYTES.length == last_cert_subject_domain.length && (short) Util.arrayCompare(DOMAIN_SUPERMARKET_BYTES, offset_0, last_cert_subject_domain, offset_0, (short) last_cert_subject_domain.length) == 0) {
            System.out.println("super market domain");
            if ((short) DOMAIN_SUPERMARKET_AUTH[(short) idx] == offset_1) {
                hasCheckAuthContent = true;
            }
        }

        if (hasCheckAuthContent) {
            byte[] temp = new byte[(short) queryResult.length];
            if (temp.length > 0) {
                Util.arrayCopy(queryResult, offset_0, temp, offset_0, (short) temp.length);
            }
            queryResult = new byte[(short) (temp.length + 2 + param.length + val.length)];
            if (temp.length > 0) {
                Util.arrayCopy(temp, offset_0, queryResult, offset_0, (short) temp.length);
            }
            queryResult[temp.length] = (byte) param.length;
            Util.arrayCopy(param, offset_0, queryResult, (short) (temp.length + 1), (short) param.length);
            queryResult[temp.length + 1 + param.length] = (byte) val.length;
            Util.arrayCopy(val, offset_0, queryResult, (short) (temp.length + 1 + param.length + 1), (short) val.length);
        }
        return hasCheckAuthContent;
    }

    private byte[] genNym() {
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        NYM = new byte[MessageDigest.LENGTH_SHA];
        byte[] temp = new byte[last_cert_subject_cn.length + serial.length];
        Util.arrayCopy(serial, offset_0, temp, (short) (0), (short) serial.length);
        Util.arrayCopy(last_cert_subject_cn, offset_0, temp, (short) (serial.length), (short) last_cert_subject_cn.length);
        md.doFinal(temp, offset_0, (short) temp.length, NYM, offset_0);
        return NYM;
    }

    private void getQuery(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short i = (short) buffer[ISO7816.OFFSET_CDATA];
        if (i <= query_result_encrypted.length / APDU_MAX_BUFF_SIZE) {
            int msgChunkLength = APDU_MAX_BUFF_SIZE;
            if (query_result_encrypted.length - (i * APDU_MAX_BUFF_SIZE) < APDU_MAX_BUFF_SIZE) {
                msgChunkLength = query_result_encrypted.length - (i * APDU_MAX_BUFF_SIZE);
            }
            if (msgChunkLength > 0) {
                byte[] msgChunk = new byte[msgChunkLength];
                System.arraycopy(query_result_encrypted, APDU_MAX_BUFF_SIZE * i, msgChunk, 0, msgChunkLength);
                System.out.println(byteArrayToHexString(msgChunk));
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) msgChunkLength);
                System.out.println("sending response with length " + msgChunkLength);
                apdu.sendBytesLong(msgChunk, offset_0, (short) msgChunkLength);
            }
        } else {
            apdu.setOutgoing();
            apdu.setOutgoingLength(offset_0);
            apdu.sendBytesLong(new byte[0], offset_0, offset_0);
        }
    }


    // ------ help functions
    // ------------------------------------------------------
    // byte array from hex string
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // hex from byte array
    private static String byteArrayToHexString(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    // find substring in byte array
    private static int arraySubstrIndex(byte[] str, byte[] substr) {
        return arraySubstrIndexFrom(str, substr, 0);
    }

    private static int arraySubstrIndexFrom(byte[] str, byte[] substr, int offset) {
        int res = -1;
        for (int i = offset; i < str.length; i++) {
            int temp_res = -1;
            if (str[i] == substr[0]) {
                temp_res = i;
                for (int j = 1; j < substr.length; j++) {
                    if (str[i + j] != substr[j]) {
                        temp_res = -1;
                        break;
                    }
                }
                if (temp_res >= 0) {
                    res = temp_res;
                    break;
                }
            }
        }
        return res;
    }

}