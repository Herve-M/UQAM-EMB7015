package apdugenerator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

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

    /**
     * Generate a Private/Public key pair
     */
    private void generateKeyPair() {
        try {
            System.out.println("Generating keys...");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(512);
            KeyPair keypair = generator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keypair.getPrivate();

            FileOutputStream publicKeyFile = new FileOutputStream("public.key");
            publicKeyFile.write(publicKey.getEncoded());
            publicKeyFile.close();

            FileOutputStream privateKeyFile = new FileOutputStream("private.key");
            privateKeyFile.write(privateKey.getEncoded());
            privateKeyFile.close();

            System.out.println("Modulus = " + publicKey.getModulus());
            System.out.println("Public Exp = " + publicKey.getPublicExponent());
            System.out.println("Private Exp = " + privateKey.getPrivateExponent());

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
     * Convert BigInt to Byte[]
     * @param big
     * @return 
     */
    byte[] getBytes(BigInteger big) {
        byte[] data = big.toByteArray();
        if (data[0] == 0) {
            byte[] tmp = data;
            data = new byte[tmp.length - 1];
            System.arraycopy(tmp, 1, data, 0, tmp.length - 1);
        }
        return data;
    }

    /**
     * Make a displayable byte[]
     * @param in
     * @return 
     */
    String byteToStr(byte[] in) {
        StringBuilder out = new StringBuilder();
        for (byte b : in) {
            out.append("0x"+String.format("%02X ", b));
        }
        return out.toString();
    }

    public void setPublicKey() {
        try {
            byte[] data = loadFile("public.key");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPublicKey key = (RSAPublicKey) factory.generatePublic(spec);

            byte[] modulus = getBytes(key.getModulus());

            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PUBLIC_MODULUS, (byte) 0,
                    (byte) 0, modulus);
            System.out.println("APDU for setting Public Key Modulus :");
            System.out.println(byteToStr(capdu.getBytes()));

            byte[] exponent = getBytes(key.getPublicExponent());
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PUBLIC_EXP, (byte) 0,
                    (byte) 0, exponent);
            System.out.println("APDU for setting Public Key Exp :");
            System.out.println(byteToStr(capdu.getBytes()));
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void setPrivateKey(){
        try{
            byte[] data = loadFile("private.key");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey key = (RSAPrivateKey) factory.generatePrivate(spec);
            
            
            byte[] modulus = getBytes(key.getModulus());
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PRIVATE_MODULUS, (byte) 0,
                    (byte) 0, modulus);
            System.out.println("APDU for setting Private Key Modulus :");
            System.out.println(byteToStr(capdu.getBytes()));
            
            byte[] exponent = getBytes(key.getPrivateExponent());
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_PRIVATE_EXP, (byte) 0,
					(byte) 0, exponent);
            System.out.println("APDU for setting Private Key Exp :");
            System.out.println(byteToStr(capdu.getBytes()));
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void setOwnerPin(){
        try {
            System.out.println("Enter PIN :");
            Scanner scanner = new Scanner(System.in);
            int choice = scanner.nextInt();
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_SET_OWNER_PIN, (byte) 0,
                    (byte) 0, choice);
            System.out.println("APDU for setting Owner Pin :");
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void verifyPin(){
        try {
            System.out.println("Enter PIN :");
            Scanner scanner = new Scanner(System.in);
            int choice = scanner.nextInt();
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_VERIFICATION, (byte) 0,
                    (byte) 0, choice);
            System.out.println("APDU for Pin verification :");
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void getCreditApdu(){
        try {
            System.out.println("Enter how many to credit :");
            Scanner scanner = new Scanner(System.in);
            int choice = scanner.nextInt();           
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_CREDIT, (byte) 0,
                    (byte) 0, choice);
            System.out.println("APDU for Credit Op. :");
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void getDebitApdu(){
        try {
            System.out.println("Enter how many to debit :");
            Scanner scanner = new Scanner(System.in);
            int choice = scanner.nextInt();           
            
            //TODO: add test ? <=4
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_DEBIT, (byte) 0,
                    (byte) 0, choice);
            System.out.println("APDU for Debit Op. :");
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void getBalanceApdu(){
        try {
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLA_APPLET, INS_BALANCE, (byte) 0,
                    (byte) 0, 0);
            System.out.println("APDU for Balance Op. :");
            System.out.println(byteToStr(capdu.getBytes()));
            
        } catch (Exception ex) {
            Logger.getLogger(APDUGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
   
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
        apdug.printMenu();
    }

}
