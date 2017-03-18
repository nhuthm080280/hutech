/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsa;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.Timestamp;
import java.util.Calendar;
import java.util.Random;

/**
 *
 * @author nhuynh8
 */
class RSA {

    /**
     * Bit length of each prime number.
     */
    int primeSize;

    /**
     * Two distinct large prime numbers p and q.
     */
    BigInteger p, q;

    /**
     * Modulus N.
     */
    BigInteger N;

    /**
     * r = ( p - 1 ) * ( q - 1 )
     */
    BigInteger r;

    /**
     * Public exponent E and Private exponent D
     */
    BigInteger E, D;
    static PrintStream pr;
    static FileOutputStream out;

    public RSA() {
    }

    public RSA(int primeSize) {
        this.primeSize = primeSize;

        // generate two distinct large prime numbers p and q
        generatePrimeNumbers();
        
        // generate Public and Private keys
        generatePublicPrivateKeys();
    }
    
    /*
    genrate two distinct large prime numbers p and q*/
    public void generatePrimeNumbers(){
        p = BigInteger.probablePrime(primeSize/2, new Random());
        
        do {            
            q = BigInteger.probablePrime(primeSize/2, new Random());
        } while (q.compareTo(p) == 0);
    }
    
    /*
    generate public and private key*/
    
    private void generatePublicPrivateKeys() {
        // N = p* q
        N = p.multiply(q);
        // r = (p-1)*(q-1)
        r = p.subtract(BigInteger.valueOf(1));
        r = r.multiply(q.subtract(BigInteger.valueOf(1)));
        
        // choose E, coprime to and less than r
        do {            
            E = new BigInteger(2*primeSize, new Random());
        } while ((E.compareTo(r) !=-1) || (E.gcd(r).compareTo(BigInteger.valueOf(1))!=0));
        // compare D, the inverse of E mod r
        D = E.modInverse(r);
    }
    
    /*
    Encrypts the plaintext (Using Public key)
    */
    public BigInteger[] encrypt(String message){
        int i;
        byte[] temp = new byte[1];
        byte[] digits = message.getBytes();
        BigInteger[] bigdigits = new BigInteger[digits.length];
        for(i =0; i< bigdigits.length; i++){
            temp[0] = digits[i];
            bigdigits[i] = new BigInteger(temp);
        }
        
        BigInteger[] encrypted = new BigInteger[bigdigits.length];
        for(i = 0; i< bigdigits.length;i++){
            encrypted[i] = bigdigits[i].modPow(E, N);
        }
        return (encrypted);

    }
    
    public BigInteger[] encrypt(String message, BigInteger userD, BigInteger userN){
         int i;
        byte[] temp = new byte[1];
         byte[] digits = message.getBytes();
         BigInteger[] bigdigits = new BigInteger[digits.length];
         
          for(i =0; i< bigdigits.length; i++){
            temp[0] = digits[i];
            bigdigits[i] = new BigInteger(temp);
        }
          
          BigInteger[] encrypted = new BigInteger[bigdigits.length];
        for(i = 0; i< bigdigits.length;i++){
            encrypted[i] = bigdigits[i].modPow(userD, userN);
        }
        return (encrypted);
          
          
    }
    
    /*
    decrypts the ciphertext using private key
    @param encrypted BigInterger array containing
    the ciphertext to be decrypted
    @return The decrypted  text
    */
    
    public String decrypt(BigInteger[] encrypted, BigInteger D, BigInteger N){
        int i;
        BigInteger[] decrypted = new BigInteger[encrypted.length];
        
        for(i = 0; i< decrypted.length;i++){
            decrypted[i]= encrypted[i].modPow(D, N);            
        }
        char[] charArray = new char[decrypted.length] ;
        
        String decryptText = "";
                for (i=0; i<decrypted.length; i++)
                {
                   charArray[i] = (char) (decrypted[i].intValue());
                }
                     return (new String(charArray));
    }

    public int getPrimeSize() {
        return primeSize;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getN() {
        return N;
    }

    public BigInteger getR() {
        return r;
    }

    public BigInteger getE() {
        return E;
    }

    public BigInteger getD() {
        return D;
    }

    public static PrintStream getPr() {
        return pr;
    }

    public static FileOutputStream getOut() {
        return out;
    }
    
    public static void main(String[] args) throws IOException{
        int primeSize = 8;
        // generate public and private key
         RSA rsa = new  RSA(primeSize);
         System.out.println("Key Size: [" + primeSize + "]");
         System.out.println("");
         System.out.println("Generated prime numbers p and q");
         System.out.println("p: [" + rsa.getP().toString(16).toLowerCase() + "]");
         System.out.println("p: [" + rsa.getQ().toString(16).toLowerCase() + "]");
         System.out.println("");
         System.out.println("The public key is the pair (N,E) which will be published.");
         System.out.println("N: ["+ rsa.getN().toString(16).toUpperCase()+"]");
         System.out.println("E: ["+ rsa.getE().toString(16).toUpperCase()+"]");       
         System.out.println("The private key is the pair (N,D) which will be kept private");
         System.out.println("N: ["+ rsa.getE().toString(16).toUpperCase()+"]");  
         System.out.println("D: ["+ rsa.getD().toString(16).toUpperCase()+"]");  
         System.out.println("");
         // get message plain text from user
         System.out.println("Please enter message (plaintext):");
         String plaintext = (new BufferedReader(new InputStreamReader(System.in))).readLine();
         System.out.println("");
         // encrypt message
         BigInteger[] ciphertext = rsa.encrypt(plaintext);
         
         System.out.println("Ciphertext: [");
         for(int i = 0; i< ciphertext.length;i++){
             System.out.print(ciphertext[i].toString(16).toUpperCase());
             if( i != ciphertext.length - 1){
                 System.out.print("");
             }
         }
         
         System.out.println("]");
         System.out.println("");
         
         RSA rsa1 = new RSA(8);
         String recoveredPlaintext = rsa1.decrypt(ciphertext, rsa.getD(), rsa.getN());
         System.out.println("Recovered plaintext: [" + recoveredPlaintext +"]");        
    
    }
 
}
