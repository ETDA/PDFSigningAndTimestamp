package main;

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;

/**
 * Time Stamping Authority (TSA) Client [RFC 3161].
 * @author Vakhtang Koroghlishvili
 * @author John Hewson
 */
public class TSAClient
{
    private static final Log LOG = LogFactory.getLog(TSAClient.class);

    private  URL url;
    private  String username;
    private  String password;
    private  MessageDigest digest;
    private  String keystoreFile;
    private  String keystorePassword;
    private  String keystoreType;
    private  Boolean isCertAuthen = false;
 
    /**
     *
     * @param url the URL of the TSA service
     * @param username user name of TSA
     * @param password password of TSA
     * @param digest the message digest to use
     */
    public TSAClient(URL url, String username, String password, MessageDigest digest)
    {
        this.url = url;
        this.username = username;
        this.password = password;
        this.digest = digest;
    }    
    
    public TSAClient(URL url, String keystoreFile, String keystorePassword,String keystoreType, MessageDigest digest)
    {
        this.url = url;
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
        this.keystoreType = keystoreType;
        this.digest = digest;
        this.isCertAuthen = true;
    }    

    /**
     *
     * @param messageImprint imprint of message contents
     * @return the encoded time stamp token
     * @throws IOException if there was an error with the connection or data from the TSA server,
     *                     or if the time stamp response could not be validated
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws KeyManagementException 
     * @throws UnrecoverableKeyException 
     */
    public byte[] getTimeStampToken(byte[] messageImprint) throws IOException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, CertificateException
    {
        digest.reset();
        byte[] hash = digest.digest(messageImprint);

        // 32-bit cryptographic nonce
        SecureRandom random = new SecureRandom();
        int nonce = random.nextInt();

        // generate TSA request
        TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
        tsaGenerator.setCertReq(true);
        ASN1ObjectIdentifier oid = getHashObjectIdentifier(digest.getAlgorithm());
        TimeStampRequest request = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce));

        // get TSA response
        byte[] tsaResponse = null ;
        
        if(isCertAuthen) {
        	tsaResponse = getTSAResponseWithCertificate(request.getEncoded());
        }
        else {
        	tsaResponse = getTSAResponse(request.getEncoded());
        }

        TimeStampResponse response;
        try
        {
            response = new TimeStampResponse(tsaResponse);
            response.validate(request);
        }
        catch (TSPException e)
        {
            throw new IOException(e);
        }
        
        TimeStampToken token = response.getTimeStampToken();
        if (token == null)
        {
            throw new IOException("Response does not have a time stamp token");
        }

        return token.getEncoded();
    }

    // gets response data for the given encoded TimeStampRequest data
    // throws IOException if a connection to the TSA cannot be established
    private byte[] getTSAResponse(byte[] request) throws IOException
    {
        LOG.debug("Opening connection to TSA server");
        
       
        // todo: support proxy servers
        URLConnection connection = url.openConnection();
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.setRequestProperty("Content-Type", "application/timestamp-query");

        String authen = new String(Base64.encode((username + ":" + password).getBytes()));

        LOG.debug("Established connection to TSA server");

        if (username != null && password != null && !username.isEmpty() && !password.isEmpty())
        {
//           connection.setRequestProperty(username, password);
        	connection.setRequestProperty("Authorization", "Basic " + authen);
        }

        // read response
        OutputStream output = null;
        try
        {
            output = connection.getOutputStream();
            output.write(request);
            output.flush();
        }
        finally
        {
            IOUtils.closeQuietly(output);
        }

        LOG.debug("Waiting for response from TSA server");

        InputStream input = null;
        byte[] response;
        try
        {
            input = connection.getInputStream();
            response = IOUtils.toByteArray(input);
        }
        finally
        {
            IOUtils.closeQuietly(input);
        }

        LOG.debug("Received response from TSA server");

        return response;
    }
    
 // gets response data for the given encoded TimeStampRequest data with with certificate
    // throws IOException if a connection to the TSA cannot be established
    private byte[] getTSAResponseWithCertificate(byte[] request) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException
    {
        LOG.debug("Opening connection to TSA server with HTTPS certificate authen");        
       
		
		Security.addProvider(new BouncyCastleProvider());
		
		KeyStore clientKeystore = KeyStore.getInstance(keystoreType);
		
		clientKeystore.load(new FileInputStream(keystoreFile), keystorePassword.toCharArray());
		
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(clientKeystore, keystorePassword.toCharArray());

		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(kmf.getKeyManagers(),null, new SecureRandom());
		SSLSocketFactory sf = ctx.getSocketFactory();
        
        // todo: support proxy servers
		HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
		connection.setSSLSocketFactory(sf);
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        connection.setRequestProperty("charset","utf-8");		


        LOG.debug("Established connection to TSA server");

		try{
			connection.connect();
		}
		catch (IOException ioe) 
		{
			throw  ioe;
		}


        // read response
        OutputStream output = null;
        try
        {
            output = connection.getOutputStream();
            output.write(request);
            output.flush();
        }
        finally
        {
            IOUtils.closeQuietly(output);
        }

        LOG.debug("Waiting for response from TSA server");

        InputStream input = null;
        byte[] response;
        try
        {
            input = connection.getInputStream();
            response = IOUtils.toByteArray(input);
        }
        finally
        {
            IOUtils.closeQuietly(input);
        }

        LOG.debug("Received response from TSA server");

        return response;
    }

    // returns the ASN.1 OID of the given hash algorithm
    private ASN1ObjectIdentifier getHashObjectIdentifier(String algorithm)
    {
        switch (algorithm)
        {
            case "MD2":
                return new ASN1ObjectIdentifier(PKCSObjectIdentifiers.md2.getId());
            case "MD5":
                return new ASN1ObjectIdentifier(PKCSObjectIdentifiers.md5.getId());
            case "SHA-1":
                return new ASN1ObjectIdentifier(OIWObjectIdentifiers.idSHA1.getId());
            case "SHA-224":
                return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha224.getId());
            case "SHA-256":
                return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.getId());
            case "SHA-384":
                return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha384.getId());
            case "SHA-512":
                return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha512.getId());
            default:
                return new ASN1ObjectIdentifier(algorithm);
        }
    }
}
