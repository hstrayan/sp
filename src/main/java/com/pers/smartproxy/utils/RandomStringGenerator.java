package com.pers.smartproxy.utils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Created by Ryan Price on 03/29/2016 as part of Project DeadBolt
 */
public class RandomStringGenerator {
	
	private static SecureRandom random = new SecureRandom();

    public static String generateRandomString(int numBits)
    {
        return new BigInteger(numBits, random).toString(32);
    }

    public static String generateClientSecret()
    {
        return generateRandomString(130);
    }

    public static String generateSalt()
    {
        return generateRandomString(64);
    }
    
   

}
