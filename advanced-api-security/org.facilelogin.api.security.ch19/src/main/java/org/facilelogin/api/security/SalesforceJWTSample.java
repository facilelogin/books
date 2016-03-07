package org.facilelogin.api.security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import javax.crypto.NoSuchPaddingException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class SalesforceJWTSample {

	// client_id of your Salesforce Connected Apps
	private static final String CLIENT_ID = "3MVG9uudbyLbNPZFFPAR17qN9_CL6.7I4xwccEh52bWVgiW49_zea7";
	// salesforce username, who the token is obtained for.
	private static final String SUBJECT = "prabath@facilelogin.com";
	// audience of the token. It must be set to https://login.salesforce.com
	private static final String AUD = "https://login.salesforce.com";
	// location of the keystore (apress.jks), which we created in step-3
	private static final String KEYSTORE_LOCATION = "/Users/prabath/git/facilelogin/books/advanced-api-security/org.facilelogin.api.security.ch19/keys/apress.jks";
	// password of the keystore, which we created in step-3
	private static final String KEYSTORE_PWD = "password";
	// password of the private key, which we created in step-3
	private static final String KEY_PWD = "password";

	public static void main(String[] args) throws ParseException, JOSEException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, UnrecoverableKeyException, CertificateException,
			FileNotFoundException, KeyStoreException, IOException {

		System.out.println(buildRsaSha256SignedJWT(getPrivateKey()));
	}

	public static PrivateKey getPrivateKey() throws NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException, UnrecoverableKeyException, KeyStoreException {

		// load the private key from a keystore
		KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(new FileInputStream(KEYSTORE_LOCATION), KEYSTORE_PWD.toCharArray());
		return (PrivateKey) keystore.getKey("apress", KEY_PWD.toCharArray());
	}

	public static String buildRsaSha256SignedJWT(PrivateKey privateKey) throws JOSEException {

		Date currentTime = new Date();

		// create a claim set.
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().
				// set the value of the issuer.
				issuer(CLIENT_ID).
				// set the subject value - JWT belongs to this subject.
				subject(SUBJECT).
				// set values for audience restriction.
				audience(AUD).
				// expiration time set to 10 minutes.
				expirationTime(new Date(new Date().getTime() + 1000 * 60 * 10)).
				// set the valid from time to current time.
				notBeforeTime(currentTime).
				// set issued time to current time.
				issueTime(currentTime).
				// set a generated UUID as the JWT identifier.
				jwtID(UUID.randomUUID().toString()).build();

		// create JWS header with RSA-SHA256 algorithm.
		JWSHeader jswHeader = new JWSHeader(JWSAlgorithm.RS256);

		// create signer with the RSA private key..
		JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);

		// create the signed JWT with the JWS header and the JWT body.
		SignedJWT signedJWT = new SignedJWT(jswHeader, jwtClaims);

		// sign the JWT with RSA-SHA256.
		signedJWT.sign(signer);

		// serialize into base64-encoded text.
		String jwtInText = signedJWT.serialize();

		return jwtInText;
	}

}
