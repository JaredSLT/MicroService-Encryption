package tech.tresearchgroup.microservices.encryption.controller;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class KeyManager {
    public static SecretKey getKeyFromPassword(String password, String salt, String algorithm, int bit, String factoryAlgorithm)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(factoryAlgorithm);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, bit);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);
    }
}
