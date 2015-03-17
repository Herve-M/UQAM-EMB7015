package cbc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
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
    //ISSUED
    static final byte INS_VERIFICATION = (byte) 0x10;
    static final byte INS_CREDIT = (byte) 0x20;
    static final byte INS_DEBIT = (byte) 0x30;
    static final byte INS_BALANCE = (byte) 0x40;

    ////STATUS WORD
    final static short SW_VERIFICATION_FAILED = 0x6300;
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    final static short SW_NEGATIVE_BALANCE = 0x6A85;

    //DATA
    static final byte PIN_MAX_LIMIT = (byte) 0x03;
    static final byte PIN_MAX_SIZE = (byte) 0x04;
    private OwnerPIN ownerPIN;
    private short balance;
    private byte state;
    byte[] tmp;

    //SECURITY
    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;
    Cipher cipher;

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
        cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        //Crypt
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        privateKey.clearKey();
        publicKey.clearKey();
        //Applet State
        state = STATE_INIT;
        //TMP
        tmp = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
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
                } else {
                    if (!ownerPIN.isValidated()) {
                        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
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
        short outBuffSize = 0;

        apdu.setOutgoing();
        
        Util.setShort(buffer, (short) 0, balance);
//        try {
//            cipher.init(publicKey, Cipher.MODE_ENCRYPT);
//            outBuffSize = cipher.doFinal(buffer,(short) 0, (byte)2,buffer, (short) 0);
//        } catch(CryptoException ex){
//            ISOException.throwIt((short)(0x9100 + ex.getReason()));
//        }        
        
        apdu.setOutgoingLength(outBuffSize);        
        apdu.sendBytes((short) 0, outBuffSize);
    }

    /**
     * Make a credit action
     *
     * @param apdu
     */
    private void insCredit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte numBytes = (byte)(buffer[ISO7816.OFFSET_LC]& 0x00FF);
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        short outBuffSize = 0;
        
//        if ((numBytes != 1) || (byteRead != 1)) {
//            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//        }
        
        try {
            cipher.init(privateKey, Cipher.MODE_DECRYPT);
            outBuffSize = cipher.doFinal(buffer,ISO7816.OFFSET_CDATA,(short)(buffer[ISO7816.OFFSET_LC] & 0x0FF),tmp,(short)0);

//            byte creditAmount = buffer[ISO7816.OFFSET_CDATA];
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
        } catch(CryptoException ex){
            JCSystem.abortTransaction();
            ISOException.throwIt((short)(0x9100 + ex.getReason()));
        }
        catch(TransactionException ex){
            ISOException.throwIt((short)(0x9200 + ex.getReason()));
        } 
    }

    /**
     * Make a debit action
     *
     * @param apdu
     */
    private void insDebit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte numBytes = (byte)(buffer[ISO7816.OFFSET_LC]& 0x00FF);
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        short outBuffSize = 0;

//        if ((numBytes != 1) || (byteRead != 1)) {
//            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//        }       
        
        cipher.init(privateKey, Cipher.MODE_DECRYPT);
        outBuffSize = cipher.doFinal(buffer,ISO7816.OFFSET_CDATA,(short)(buffer[ISO7816.OFFSET_LC] & 0x0FF),tmp,(short)0);
        
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
    }

    /**
     * Verify PIN
     *
     * @param apdu
     */
    private void insVerification(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short outBuffSize = 0;
        
        if(privateKey.isInitialized()){
            try{
                cipher.init(privateKey, Cipher.MODE_DECRYPT);
                outBuffSize = cipher.doFinal(buffer,ISO7816.OFFSET_CDATA,(short)(buffer[ISO7816.OFFSET_LC] & 0x0FF),tmp,(short)0);
            }
            catch(CryptoException ex){
                ISOException.throwIt((short)(0x9100 + ex.getReason()));
            }
        }
              
        if (ownerPIN.check(tmp, (short)0, (byte) outBuffSize) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
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
        ownerPIN.update(buffer, ISO7816.OFFSET_CDATA, (byte)(buffer[ISO7816.OFFSET_LC]& 0x00FF));
        JCSystem.commitTransaction();
    }
    
    /**
     * Set Modulus of public key
     * @param apdu
     * @param lc 
     */
    void insSetPublicModulus(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        try {
            JCSystem.beginTransaction();
            publicKey.setModulus(buffer, ISO7816.OFFSET_CDATA, (short)(buffer[ISO7816.OFFSET_LC]& 0x00FF));
            JCSystem.commitTransaction();
        } catch (CryptoException ex){
            JCSystem.abortTransaction();
            ISOException.throwIt((short)(0x9100 + ex.getReason()));
        }
        catch(TransactionException ex){
            ISOException.throwIt((short)(0x9200 + ex.getReason()));
        }
    }
   /**
    * Set Modulus of private key
    * @param apdu
    * @param lc 
    */
    void insSetPrivateModulus(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        try{
            JCSystem.beginTransaction();
            privateKey.setModulus(buffer, ISO7816.OFFSET_CDATA, (short)(buffer[ISO7816.OFFSET_LC]& 0x00FF));
            JCSystem.commitTransaction();
        }
        catch(CryptoException ex){
            JCSystem.abortTransaction();
            ISOException.throwIt((short)(0x9100 + ex.getReason()));
        }
        catch(TransactionException ex){
            ISOException.throwIt((short)(0x9200 + ex.getReason()));
        }
    }
    
    /**
     * Set Exponent of private key
     * @param apdu
     * @param lc 
     */
    void insSetPrivateExp(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        try{
            JCSystem.beginTransaction();
            privateKey.setExponent(buffer, ISO7816.OFFSET_CDATA, (short)(buffer[ISO7816.OFFSET_LC]& 0x00FF));
            JCSystem.commitTransaction();
        }
        catch(CryptoException ex){
            JCSystem.abortTransaction();
            ISOException.throwIt((short)(0x9100 + ex.getReason()));
        }
        catch(TransactionException ex){
            ISOException.throwIt((short)(0x9200 + ex.getReason()));
        }
    }
    
    /**
     * Set Exponent of public key
     * @param apdu
     * @param lc 
     */
    void insSetPublicExp(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        try{
            JCSystem.beginTransaction();
            publicKey.setExponent(buffer, ISO7816.OFFSET_CDATA, (short)(buffer[ISO7816.OFFSET_LC]& 0x00FF));
            JCSystem.commitTransaction();
        }
        catch(CryptoException ex){
            JCSystem.abortTransaction();
            ISOException.throwIt((short)(0x9100 + ex.getReason()));
        }
        catch(TransactionException ex){
            ISOException.throwIt((short)(0x9200 +ex.getReason()));
        }
    }
    
    void insSetIssued(){
        state = STATE_ISSUED;
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
