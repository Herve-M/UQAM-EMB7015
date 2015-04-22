/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptedbankterminal;

import com.licel.jcardsim.base.Simulator;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javacard.framework.AID;
import javacard.security.CryptoException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author MATYSIAK Herve <herve.matysiak@viacesi.fr>
 */
public class CryptedBankTerminal {
    
    //CLA ID
    static final byte CLA_APPLET = (byte) 0xB0;

    //
    static final byte[] APPLET_AID = {(byte) 0xC3, (byte) 0x5E,
        (byte) 0x4F, (byte) 0x14, (byte) 0x37, (byte) 0x6B};

    //Applet State
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
    
    
    static final String ALGORITHM = "RSA";
    static final int ALGORITHM_KEY_SIZE = 512;
    static final String TERMINAL_PUBLIC_KEY_FILE ="term-public.key";
    static final String TERMINAL_PRIVATE_KEY_FILE ="term-private.key";
    static final String CARD_PUBLIC_KEY_FILE ="card-public.key";
    static final String CARD_PRIVATE_KEY_FILE ="card-private.key";
    
    private RSAPublicKey publicKeyCard;
    private RSAPrivateKey privateKeyCard;
    private RSAPublicKey publicKeyTerm;
    private RSAPrivateKey privateKeyTerm;
    Simulator simulator;
    
    //DATA
    static final byte MAGIC_VALUE = (byte) 0x5f3759df;

    //
    Cipher cipherDES;
    Signature signature;
    SecretKey key;
    
    ////OTHER
    public boolean EXIT = false;
    boolean anError = false;
    
    public CryptedBankTerminal() {
        try {
            signature = Signature.getInstance("SHA1withRSA");
            cipherDES = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.initSimulator();
    }
    
    /**
     * Generate a Private/Public key pair
     */
    private void generateKeyPair() {
        try {
            System.out.println("Generating keys...");
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(ALGORITHM_KEY_SIZE);
            KeyPair keypair = generator.generateKeyPair();
            RSAPublicKey cardPublicKey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey cardPrivateKey = (RSAPrivateKey) keypair.getPrivate();
            keypair = generator.generateKeyPair();
            RSAPublicKey termPublicKey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey termPrivateKey = (RSAPrivateKey) keypair.getPrivate();

            try (FileOutputStream publicKeyFile = new FileOutputStream(CARD_PUBLIC_KEY_FILE)) {
                publicKeyFile.write(cardPublicKey.getEncoded());
            }

            try (FileOutputStream privateKeyFile = new FileOutputStream(CARD_PRIVATE_KEY_FILE)) {
                privateKeyFile.write(cardPrivateKey.getEncoded());
            }

            try (FileOutputStream termPublicKeyFile = new FileOutputStream(TERMINAL_PUBLIC_KEY_FILE)) {
                termPublicKeyFile.write(termPublicKey.getEncoded());
            }

            try (FileOutputStream termPrivateKeyFile = new FileOutputStream(TERMINAL_PRIVATE_KEY_FILE)) {
                termPrivateKeyFile.write(termPrivateKey.getEncoded());
            }

            System.out.println("Card KeyPair info. : ");
            System.out.println("Modulus = " + cardPublicKey.getModulus());
            System.out.println("Public Exp = " + cardPublicKey.getPublicExponent());
            System.out.println("Private Exp = " + cardPrivateKey.getPrivateExponent());

            System.out.println("Terminal KeyPair info. : ");
            System.out.println("Modulus = " + termPublicKey.getModulus());
            System.out.println("Public Exp = " + termPublicKey.getPublicExponent());
            System.out.println("Private Exp = " + termPrivateKey.getPrivateExponent());

            this.loadKey();

        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Generic loading func.
     * @param fileName
     * @return 
     */
    private byte[] loadFile(String fileName) {
        File file = new File(fileName);
        FileInputStream fileInputStream = null;

        try {
            fileInputStream = new FileInputStream(file);

            System.out.println("Total file size to read (in bytes) : "
                    + fileInputStream.available());

            int length = fileInputStream.available();
            byte[] data = new byte[length];
            fileInputStream.read(data);
            fileInputStream.close();
            return data;
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return null;
    }
    
    /**
     * Load Public Card key
     */
    public void loadKey(){
        try {
            //Card
            {
                byte[] data = loadFile(CARD_PUBLIC_KEY_FILE);
                if (data != null) {
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
                    KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
                    publicKeyCard = (RSAPublicKey) factory.generatePublic(spec);
                }
            }
            {
                byte[] data = loadFile(CARD_PRIVATE_KEY_FILE);
                if (data != null) {
                    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
                    KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
                    privateKeyCard = (RSAPrivateKey) factory.generatePrivate(spec);
                }
            }
            //Term
            {
                byte[] data = loadFile(TERMINAL_PUBLIC_KEY_FILE);
                if (data != null) {
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
                    KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
                    publicKeyTerm = (RSAPublicKey) factory.generatePublic(spec);
                }
            }
            {
                byte[] data = loadFile(TERMINAL_PRIVATE_KEY_FILE);
                if (data != null) {
                    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
                    KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
                    privateKeyTerm = (RSAPrivateKey) factory.generatePrivate(spec);
                }
            }
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void setPublicKey() {
        try {            
            byte[] signedModulus = publicKeyTerm.getModulus().toByteArray();
            byte[] unsignedModulus = new byte[signedModulus.length - 1];
            
            if(signedModulus[0] == (byte)0x00){
                 System.arraycopy(signedModulus, 1, unsignedModulus, 0, unsignedModulus.length);
            }

            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PUBLIC_MODULUS, (byte) 0,
                    (byte) 0, unsignedModulus);
            System.out.println("APDU for setting Public Key Modulus :");
            sendCommand(capdu, 36864);

            byte[] exponent = publicKeyTerm.getPublicExponent().toByteArray();
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PUBLIC_EXP, (byte) 0,
                    (byte) 0, exponent);
            System.out.println("APDU for setting Public Key Exp :");
            sendCommand(capdu, 36864);
        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void setPrivateKey(){
        try{           
            byte[] signedModulus = privateKeyCard.getModulus().toByteArray();
            byte[] unsignedModulus = new byte[signedModulus.length - 1];
            
            if(signedModulus[0] == (byte)0x00){
                 System.arraycopy(signedModulus, 1, unsignedModulus, 0, unsignedModulus.length);
            }
            
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PRIVATE_MODULUS, (byte) 0,
                    (byte) 0, unsignedModulus);
            System.out.println("APDU for setting Private Key Modulus ["+unsignedModulus.length+"] :");
            sendCommand(capdu, 36864);
            
            byte[] exponent = privateKeyCard.getPrivateExponent().toByteArray();
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PRIVATE_EXP, (byte) 0,
					(byte) 0, exponent);
            System.out.println("APDU for setting Private Key Exp :");
            sendCommand(capdu, 36864);
        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void testPublicKey() {
        try {
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_TEST_PUBLIC_KEY, (byte) 0,
                    (byte) 0);
            System.out.println("APDU for validating Public key sent.");
            this.sendCommand(capdu, 36864);

        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void testPrivateKey() {
        try {
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_TEST_PRIVATE_KEY, (byte) 0,
                    (byte) 0);
            System.out.println("APDU for validating Private key sent.");
            this.sendCommand(capdu, 36864);

        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void setOwnerPin(){
        try {
            System.out.println("Enter PIN :");
            Scanner scanner = new Scanner(System.in);
            BigInteger choice = scanner.nextBigInteger();
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_OWNER_PIN, (byte) 0,
                    (byte) 0, choice.toByteArray());
            System.out.println("APDU for setting Owner Pin :");
            sendCommand(capdu, 36864);
            
        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void verifyPin(){
        try {
            System.out.println("Enter PIN :");
            Scanner scanner = new Scanner(System.in);
            BigInteger choice = scanner.nextBigInteger();
            
            byte[] bChoice = choice.toByteArray();
            byte[] cChoice = cryptDataWithDES(bChoice);
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_VERIFICATION, (byte) 0,
                    (byte) 0, cChoice);
            System.out.println("APDU for Pin verification ["+capdu.getData().length+"]:");
            sendCommand(capdu, 36864);
            
        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void setIssued(){
        try {
            System.out.println("Sending Issue APDU !");
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_ISSUED, 0, 0);
            sendCommand(capdu, 36864);
            
        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void initializeSession() {
        try {

            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SESSION_INIT, (byte) 0,
                    (byte) 0);
            System.out.println("APDU for asking Session key sent.");
            this.sendCommand(capdu, 36864);

        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void getCreditApdu(){
        try {
            System.out.println("Enter how many to credit :");
            Scanner scanner = new Scanner(System.in);
            BigInteger choice = scanner.nextBigInteger();
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_CREDIT, (byte) 0,
                    (byte) 0, cryptDataWithDES(choice.toByteArray()));
            System.out.println("APDU for Credit Op. :"+capdu.getData().length);
            sendCommand(capdu, 36864);
            
        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void getDebitApdu(){
        try {
            System.out.println("Enter how many to debit :");
            Scanner scanner = new Scanner(System.in);
            BigInteger choice = scanner.nextBigInteger();           
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_DEBIT, (byte) 0,
                    (byte) 0, cryptDataWithDES(choice.toByteArray()));
            System.out.println("APDU for Debit Op. :");
            sendCommand(capdu, 36864);
            
        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void getBalanceApdu(){
        try {
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_BALANCE, (byte) 0,
                    (byte) 0, (byte) 0);
            System.out.println("APDU for Balance Op. :");
            sendCommand(capdu, 36864);
            
        } catch (Exception ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private byte[] cryptDataWithRSA(byte[] data) {
        byte[] cipherData = null;
        try {
            final javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RSA");
            c.init(javax.crypto.Cipher.ENCRYPT_MODE, publicKeyCard);
            cipherData = c.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cipherData;
    }

    private byte[] cryptDataWithDES(byte[] data) {
        byte[] cipherData = null;
        try {
            cipherDES.init(Cipher.ENCRYPT_MODE, key);
            cipherData = cipherDES.doFinal(data);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cipherData;
    }

    private byte[] deCryptDataWithRSA(byte[] data) {
        byte[] cipherData = null;
        try {
            final javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RSA");
            c.init(javax.crypto.Cipher.DECRYPT_MODE, privateKeyTerm);
            cipherData = c.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cipherData;
    }

    private byte[] deCryptDataWithDES(byte[] data) {
        byte[] cipherData = null;
        try {
            cipherDES.init(Cipher.DECRYPT_MODE, key);
            cipherData = cipherDES.doFinal(data);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cipherData;
    }
    
    private void getSessionKey(byte[] data) {
        try {
            int dataLength = (publicKeyCard.getModulus().toByteArray().length - 1);
            byte[] cryptedData = new byte[dataLength];
            byte[] uncryptedData = new byte[dataLength];
            byte[] signatureData = new byte[dataLength];
            byte[] sessionKey = new byte[24];

            System.arraycopy(data, 0, cryptedData, 0, cryptedData.length);
            System.arraycopy(data, dataLength, signatureData, 0, signatureData.length);

            signature.initVerify(publicKeyCard);
            signature.update(cryptedData);
            if (signature.verify(signatureData)) {
                uncryptedData = deCryptDataWithRSA(cryptedData);
                System.arraycopy(uncryptedData, 0, sessionKey, 0, 16);
                System.arraycopy(uncryptedData, 0, sessionKey, 16, 8);
                key = new SecretKeySpec(sessionKey, "DESede");
                System.out.println("System get a Session Key");
            } else {
                System.err.println("Signature not valide !");
            }
        } catch (InvalidKeyException | SignatureException | CryptoException ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void getResponseMessage(byte[] data) {
        try {
            byte[] receivedData = deCryptDataWithDES(data);
            System.out.println("Get Data : " + new String(receivedData, Charset.defaultCharset()));
        } catch (CryptoException ex) {
            Logger.getLogger(CryptedBankTerminal.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void initializeCard() {
        this.setPrivateKey();
        this.setPublicKey();
        this.testPublicKey();
        this.testPrivateKey();
        this.setOwnerPin();
        if (!anError) {
            this.setIssued();
        }
    }
    
    private void sendCommand(CommandAPDU aPDU, int waitedValue) {
        if (aPDU != null) {
            ResponseAPDU responseAPDU = new ResponseAPDU(simulator.transmitCommand(aPDU.getBytes()));
            int sw = responseAPDU.getSW();
            if (sw == waitedValue) {
                switch (aPDU.getINS()) {
                    case INS_SESSION_INIT:
                        this.getSessionKey(responseAPDU.getData());
                        break;
                    case INS_BALANCE:
                        this.getResponseMessage(responseAPDU.getData());
                        break;
                    default:
                        System.out.println("Command validated SW : " + Integer.toHexString(sw));
                        break;
                }
            } else {
                anError = true;
                switch (aPDU.getINS()) {
                    case INS_SESSION_INIT:
                        System.out.println("Session can't be etablished. SW : " + Integer.toHexString(sw));
                        break;
                    case INS_SET_PRIVATE_EXP:
                        System.out.println("Error at setting Private Exponent ! SW : " + Integer.toHexString(sw));
                        break;
                    case INS_SET_PRIVATE_MODULUS:
                        System.out.println("Error at setting Private Modulus ! SW : " + Integer.toHexString(sw));
                        break;
                    case INS_SET_PUBLIC_EXP:
                        System.out.println("Error at setting Public Exponent ! SW : " + Integer.toHexString(sw));
                        break;
                    case INS_SET_PUBLIC_MODULUS:
                        System.out.println("Error at setting Public Modulus ! SW : " + Integer.toHexString(sw));
                        break;
                    case INS_TEST_PRIVATE_KEY:
                        System.out.println("Error at Private Key validation ! SW : " + Integer.toHexString(sw));
                        break;
                    case INS_TEST_PUBLIC_KEY:
                        System.out.println("Error at Public Key validation ! SW : " + Integer.toHexString(sw));
                        break;
                    case INS_SET_ISSUED:
                        System.out.println("Error at setting card as Issued ! SW : " + Integer.toHexString(sw));
                        break;
                    case INS_VERIFICATION:
                        this.verifyPin();
                        break;
                    case INS_CREDIT:
                        switch(Integer.toHexString(sw)){
                            case "6301":{
                                System.err.println("Need PIN Verification");
                                break;
                            }
                            case "6303":{
                                System.err.println("Session Key not valide");
                                break;
                            }
                            case "6304":{
                                System.err.println("Magic Key not valide");
                                break;
                            }
                            case "6A83":{
                                System.err.println("Invalide transaction amount");
                                break;
                            }
                            case "6A84":{
                                System.err.println("Exceed maximum balance");
                                break;
                            }
                        }
                        break;
                    case INS_DEBIT:
                        switch(Integer.toHexString(sw)){
                            case "6301":{
                                System.err.println("Need PIN Verification");
                                break;
                            }
                            case "6303":{
                                System.err.println("Session Key not valide");
                                break;
                            }
                            case "6304":{
                                System.err.println("Magic Key not valide");
                                break;
                            }
                            case "6A83":{
                                System.err.println("Invalide transaction amount");
                                break;
                            }
                            case "6A85":{
                                System.err.println("Negative balance");
                                break;
                            }
                        }
                        break;
                    default:
                        System.err.println("Unknow Instruction SW :" + Integer.toHexString(sw));
                        break;
                }
            }
        }
    }
    
    private void initSimulator(){
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        simulator = new Simulator();
        simulator.installApplet(aid, cbc.CryptedBankCard.class);
        simulator.selectApplet(aid);
        this.loadKey();
    }
    
    public void printMenu(){
        System.out.println("Select one option :");
        System.out.println("1 - Initialize Card");
        System.out.println("2 - Initialize Session");
        System.out.println("3 - Verify PIN");
        System.out.println("4 - Credit Op.");
        System.out.println("5 - Debit Op.");
        System.out.println("6 - Balance Op.");
        System.out.println("10 - Quit");
        Scanner scanner = new Scanner(System.in);
        int choice = scanner.nextInt();
        switch (choice) {
            case 0:
                this.generateKeyPair();
                break;
            case 1:
                this.initializeCard();
                break;
            case 2:
                this.initializeSession();
                break;
            case 3:
                this.verifyPin();
                return;
            case 4:
                this.getCreditApdu();
                return;
            case 5:
                this.getDebitApdu();
                return;
            case 6:
                this.getBalanceApdu();
                return;
            case 10:
                this.EXIT = true;
                return;
            default:
                this.printMenu();
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {        
        
        CryptedBankTerminal bankTerminal = new CryptedBankTerminal();
        while (!bankTerminal.EXIT) {            
            bankTerminal.printMenu();
        } 
    }
    
}
