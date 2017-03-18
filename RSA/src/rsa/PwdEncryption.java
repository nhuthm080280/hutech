/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsa;

import java.math.BigInteger;
import java.util.Scanner;
import sun.applet.Main;

/**
 *
 * @author nhuynh8
 */
public class PwdEncryption {
    public static void main(String args[]){
        Scanner in = new Scanner(System.in);
        String nhash;
        BigInteger[] ciphertext = null;
        BigInteger n = null;
        BigInteger d = null;
        String password="";
        System.out.println("Enter text to be encryoted:");
        password = in.nextLine();
        
        System.out.println("Password (Input):" + password);
        // 8FD1 5FB3 5057 5FB3 65E63AB879713ABB

        RSA rsa = new RSA(8);
        n = rsa.getN();
        d = rsa.getD();
        ciphertext = rsa.encrypt(password);
        
        StringBuffer bf = new StringBuffer();
        for(int i =0; i< ciphertext.length; i++){
            bf.append(ciphertext[i].toString(16).toUpperCase());
            if(i!= ciphertext.length - 1){
                System.out.println(" ");
            }
        }
        
        String message = bf.toString();
        System.out.println("Encrypted message:" + message);
        String dhash = rsa.decrypt(ciphertext,d,n);
        System.out.println("Decrypted message:" + dhash);
        
        
    }
}
