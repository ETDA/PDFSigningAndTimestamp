package main;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.Store;

import main.util.X509Util;

/**
 * The SignAndTimeStamp class is used to sign PDF(.pdf) with TSA 
 * 
 * @author ETDA
 *
 */
public class SignAndTimeStamp implements SignatureInterface {
	private static PrivateKey privateKey;
	private static Certificate certificate;
	private static TSAClient tsaClient;
	private static Certificate[] certificateChain;

	boolean signPdf(File pdfFile, File signedPdfFile) throws IOException {
		PDDocument doc = null;
		try {
			
			doc = PDDocument.load(pdfFile);
			OutputStream fos = new FileOutputStream(signedPdfFile);
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setSignDate(Calendar.getInstance());

			COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
			catalogDict.setNeedToBeUpdated(true);

			// =========================== For LTV Enable ===========================
			
			//Sorted Certificate 0 = E Entity , 1 = intermediate , 2 = root	 			
			Certificate[] sortedCertificateChain = X509Util.SortX509Chain(certificateChain,certificate);
			certificateChain = sortedCertificateChain;
			
			//Assign byte array for storing certificate in DSS Store.
			byte[][] certs = new byte[certificateChain.length][];
			
			//Assign byte array for storing certificate in DSS Store.
			List<CRL> crlList = new ArrayList<CRL>();
			
			//Fill certificate byte and CRLS
			for(int i =0;i<certificateChain.length;i++){
				certs[i] = certificateChain[i].getEncoded();
				if(i==certificateChain.length-1) {break;}
				crlList.addAll(new DssHelper().readCRLsFromCert((X509Certificate) certificateChain[i]));
			}
			
			//Loop getting All CRLS	        
			byte[][] crls = new byte[crlList.size()][];
			for (int i = 0 ; i < crlList.size();i++) {
				crls[i] = ( (X509CRL) crlList.get(i)).getEncoded();
			}
			
			Iterable<byte[]> certifiates = Arrays.asList(certs);
			COSDictionary dss = new DssHelper().createDssDictionary(certifiates,Arrays.asList(crls) , null);
			catalogDict.setItem(COSName.getPDFName("DSS"), dss);
			
			// =========================== For LTV Enable =========================== */
			
			// For big certificate chain
			SignatureOptions signatureOptions = new SignatureOptions();
			signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
			
			doc.addSignature(signature, this, signatureOptions);
			doc.saveIncremental(fos);

			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			if(doc != null){
				doc.close();
			}
		}
	}

	@Override
	public byte[] sign(InputStream is) throws IOException {
		try {
			List<Certificate> certList = new ArrayList<>();
			certList.addAll(Arrays.asList(certificateChain));
			@SuppressWarnings("rawtypes")
			Store certStore = new JcaCertStore(certList);

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
					.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));
			ContentSigner sha512Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
			
			gen.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
							.build(sha512Signer, new X509CertificateHolder(cert)));
			gen.addCertificates(certStore);
			
			CMSProcessableInputStream msg = new CMSProcessableInputStream(is);
			CMSSignedData signedData = gen.generate(msg,false);
			
			if(tsaClient!= null)
				signedData = signTimeStamps(signedData);

			return signedData.getEncoded();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	/**
	 * 
	 * The signWithTSA(String, String, String, String, String, String) method is used to sign PDF(.pdf) with TSA 
	 * 
	 * @param passwordP12 : password of keystore, e.g. 123, 5A754
	 * @param inputFileP12 : name of input keystore file, e.g. xxx.p12, abc.p12
	 * @param inputFileName : name of input PDf file, e.g. Test.pdf, Cost.pdf
	 * @param outputFile : name of output file, e.g. Summary.pdf, Final.pdf  
	 * @param filePath : path of file, e.g. C:/Users/cat/, C:/Doc_PDFA3/ 
	 * @param urlTsaClient : the URL of the Time-Stamping Authority(TSA) service.
	 * you can use empty string("") or null if you don't have urlTsaClient, e.g. http://10.0.0.27/, "", null
	 * @throws IOException 
	 * @throws GeneralSecurityException
	 * @throws SignatureException
	 * 
	 */
	public static void signWithTSA(String passwordP12, String inputFileP12, String inputFileName, String outputFile,
			String filePath, String tsaUrl, String keystorePath, String keystorePassword, String keystoreType)
			throws IOException, GeneralSecurityException, SignatureException {
		
		KeyStore keystore = null;
		char[] password = passwordP12.toCharArray();
		
		if(keystoreType.equals("PKCS12")) {
			keystore = KeyStore.getInstance(keystoreType);
			keystore.load(new FileInputStream(filePath + inputFileP12), password);
		}
		
		else if(keystoreType.equals("PKCS11")) {	
			String configString = "";
			configString = new String(Files.readAllBytes(Paths.get(filePath + inputFileP12)));
			
			ByteArrayInputStream confStream = new ByteArrayInputStream(configString.getBytes());		
			Provider p = new sun.security.pkcs11.SunPKCS11(confStream);
			Security.addProvider(p);
			
			keystore = KeyStore.getInstance(keystoreType,p);
			keystore.load(null,password);
		}

		Enumeration<String> aliases = keystore.aliases();
		while(aliases.hasMoreElements()) {
            String alias = (String)aliases.nextElement();
            privateKey = (PrivateKey) keystore.getKey(alias, password);
            certificate = keystore.getCertificate(alias);
            certificateChain = keystore.getCertificateChain(alias);
        }

		if(!tsaUrl.isEmpty() && tsaUrl != null){
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			tsaClient = new TSAClient(new URL(tsaUrl), filePath+keystorePath,
					keystorePassword,"PKCS12", digest);
		}
		
		File inFile = new File(filePath + inputFileName);
		File outFile = new File(filePath + outputFile);
		new SignAndTimeStamp().signPdf(inFile, outFile);
	}
	

	
	private CMSSignedData signTimeStamps(CMSSignedData signedData)
            throws IOException, TSPException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, CertificateException
    {
        SignerInformationStore signerStore = signedData.getSignerInfos();
        List<SignerInformation> newSigners = new ArrayList<>();

        for (SignerInformation signer : signerStore.getSigners())
        {
            newSigners.add(signTimeStamp(signer));
        }

        // TODO do we have to return a new store?
        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
    }
	private SignerInformation signTimeStamp(SignerInformation signer)
            throws IOException, TSPException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, CertificateException
    {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (unsignedAttributes != null)
        {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        byte[] token = tsaClient.getTimeStampToken(signer.getSignature());
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
        ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

        vector.add(signatureTimeStamp);
        Attributes signedAttributes = new Attributes(vector);

        SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(
                signer, new AttributeTable(signedAttributes));
        
        if (newSigner == null)
        {
            return signer;
        }

        return newSigner;
    }
}