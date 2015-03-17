package apdugenerator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Arrays;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

import javax.smartcardio.*;

/**
 *
 * @author Hervé
 */
public class APDUGenerator {

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
    //ISSUED
    static final byte INS_VERIFICATION = (byte) 0x10;
    static final byte INS_CREDIT = (byte) 0x20;
    static final byte INS_DEBIT = (byte) 0x30;
    static final byte INS_BALANCE = (byte) 0x40;
    
    ////Crypt
    static final String ALGORITHM = "RSA";
    static final String TERMINAL_PUBLIC_KEY_FILE ="term-public.key";
    static final String TERMINAL_PRIVATE_KEY_FILE ="term-private.key";
    static final String CARD_PUBLIC_KEY_FILE ="card-public.key";
    static final String CARD_PRIVATE_KEY_FILE ="card-private.key";
    RSAPublicKey rSAPublicKey;
    
    ////OTHER
    public boolean EXIT = false;
    

    /**
     * Generate a Private/Public key pair
     */
    private void generateKeyPair() {
        try {
            System.out.println("Generating keys...");
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(1024);
            KeyPair keypair = generator.generateKeyPair();
            RSAPublicKey cardPublicKey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey cardPrivateKey = (RSAPrivateKey) keypair.getPrivate();
            keypair = generator.generateKeyPair();
            RSAPublicKey termPublicKey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey termPrivateKey = (RSAPrivateKey) keypair.getPrivate();

            FileOutputStream publicKeyFile = new FileOutputStream(CARD_PUBLIC_KEY_FILE);
            publicKeyFile.write(cardPublicKey.getEncoded());
            publicKeyFile.close();

            FileOutputStream privateKeyFile = new FileOutputStream(CARD_PRIVATE_KEY_FILE);
            privateKeyFile.write(cardPrivateKey.getEncoded());
            privateKeyFile.close();
            
            FileOutputStream termPublicKeyFile = new FileOutputStream(TERMINAL_PUBLIC_KEY_FILE);
            termPublicKeyFile.write(termPublicKey.getEncoded());
            termPublicKeyFile.close();

            FileOutputStream termPrivateKeyFile = new FileOutputStream(TERMINAL_PRIVATE_KEY_FILE);
            termPrivateKeyFile.write(termPrivateKey.getEncoded());
            termPrivateKeyFile.close();
            
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
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
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
            byte[] data = loadFile(CARD_PUBLIC_KEY_FILE);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            rSAPublicKey = (RSAPublicKey) factory.generatePublic(spec);
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Make a displayable byte[]
     * @param in
     * @return 
     */
    private String byteToStr(byte[] in) {
        StringBuilder out = new StringBuilder();
        for (byte b : in) {
            out.append("0x"+String.format("%02X ", b));
        }
        return out.toString();
    }

    private void setPublicKey() {
        try {
            byte[] data = loadFile(TERMINAL_PUBLIC_KEY_FILE);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            RSAPublicKey key = (RSAPublicKey) factory.generatePublic(spec);
            
            byte[] signedModulus = key.getModulus().toByteArray();
            byte[] unsignedModulus = new byte[signedModulus.length - 1];
            
            if(signedModulus[0] == (byte)0x00){
                 System.arraycopy(signedModulus, 1, unsignedModulus, 0, unsignedModulus.length);
            }

            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PUBLIC_MODULUS, (byte) 0,
                    (byte) 0, unsignedModulus);
            System.out.println("APDU for setting Public Key Modulus :");
            System.out.println(byteToStr(capdu.getBytes()));

            byte[] exponent = key.getPublicExponent().toByteArray();
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PUBLIC_EXP, (byte) 0,
                    (byte) 0, exponent);
            System.out.println("APDU for setting Public Key Exp :");
            System.out.println(byteToStr(capdu.getBytes()));
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void setPrivateKey(){
        try{
            byte[] data = loadFile(CARD_PRIVATE_KEY_FILE);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            RSAPrivateKey key = (RSAPrivateKey) factory.generatePrivate(spec);
            
            byte[] signedModulus = key.getModulus().toByteArray();
            byte[] unsignedModulus = new byte[signedModulus.length - 1];
            
            if(signedModulus[0] == (byte)0x00){
                 System.arraycopy(signedModulus, 1, unsignedModulus, 0, unsignedModulus.length);
            }
            
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PRIVATE_MODULUS, (byte) 0,
                    (byte) 0, unsignedModulus);
            System.out.println("APDU for setting Private Key Modulus ["+unsignedModulus.length+"] :");
            System.out.println(byteToStr(capdu.getBytes()));
            
            byte[] exponent = key.getPrivateExponent().toByteArray();
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PRIVATE_EXP, (byte) 0,
					(byte) 0, exponent);
            System.out.println("APDU for setting Private Key Exp :");
            System.out.println(byteToStr(capdu.getBytes()));
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
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
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void verifyPin(){
        try {
            System.out.println("Enter PIN :");
            Scanner scanner = new Scanner(System.in);
            BigInteger choice = scanner.nextBigInteger();
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_VERIFICATION, (byte) 0,
                    (byte) 0, crypt(choice.toByteArray()));
            System.out.println("APDU for Pin verification ["+capdu.getData().length+"]:");
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
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
                    (byte) 0, crypt(choice.toByteArray()));
            System.out.println("APDU for Credit Op. :"+capdu.getData().length);
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
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
                    (byte) 0, crypt(choice.toByteArray()));
            System.out.println("APDU for Debit Op. :");
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void getBalanceApdu(){
        try {
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_BALANCE, (byte) 0,
                    (byte) 0, (byte) 0);
            System.out.println("APDU for Balance Op. :");
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Crypt a set of Data with CardPublicKey
     * @param data
     * @return 
     */
    private byte[] crypt(byte[] data){
        byte[] cipherData = null;
        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, rSAPublicKey);
            cipherData = cipher.doFinal(data);
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cipherData;
    }
    
    //Just for info
//    private byte[] decrypt(byte[] data){
//        byte[] cipherData = null;
//        try {
//            byte[] dataF = loadFile(CARD_PRIVATE_KEY_FILE);
//            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(dataF);
//            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
//            RSAPrivateKey key = (RSAPrivateKey) factory.generatePrivate(spec);        
//            
//            final Cipher cipher = Cipher.getInstance(ALGORITHM);
//            cipher.init(Cipher.DECRYPT_MODE, key);
//            cipherData = cipher.doFinal(data);
//        } catch (Exception ex) {
//            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        return cipherData;
//    }    
    
    public void printMenu(){
        System.out.println("Select one option :");
        System.out.println("1 - Generate KeyPair");
        System.out.println("2 - Get Private Key APDU");
        System.out.println("3 - Get Public Key APDU");
        System.out.println("4 - Get PIN APDU");
        System.out.println("5 - Get PIN Verification APDU");
        System.out.println("6 - Get Credit APDU");
        System.out.println("7 - Get Debit APDU");
        System.out.println("8 - Get Balance APDU");
        System.out.println("9 - Quit");
        Scanner scanner = new Scanner(System.in);
        int choice = scanner.nextInt();
        switch (choice) {
            case 1:
                this.generateKeyPair();
                break;
            case 2:
                this.setPrivateKey();
                break;
            case 3:
                this.setPublicKey();
                break;
            case 4:
                this.setOwnerPin();
                return;
            case 5:
                this.verifyPin();
                return;
            case 6:
                this.getCreditApdu();
                return;
            case 7:
                this.getDebitApdu();
                return;
            case 8:
                this.getBalanceApdu();
                return;
            case 9:
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
        APDUGenerator apdug = new APDUGenerator();
        apdug.loadKey();
        while (!apdug.EXIT) {            
            apdug.printMenu();
        }        
    }

}
