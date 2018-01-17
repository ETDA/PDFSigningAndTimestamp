

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
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

	boolean signPdf(File pdfFile, File signedPdfFile) {

		try (OutputStream fos = new FileOutputStream(signedPdfFile); 
			PDDocument doc = PDDocument.load(pdfFile)) {

			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setSignDate(Calendar.getInstance());

			COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
//			COSDictionary permsDict = new COSDictionary();
//			catalogDict.setItem(COSName.PERMS, permsDict);
//			permsDict.setItem(COSName.getPDFName("FieldMDP"), signature);
			catalogDict.setNeedToBeUpdated(true);
//			permsDict.setNeedToBeUpdated(true);
			
			// =========================== For LTV Enable ===========================
	        byte[][] certs = new byte[certificateChain.length][];
	        for(int i =0;i<certificateChain.length;i++){
	        	certs[i] = certificateChain[i].getEncoded();
	        }
	        
	        List<CRL> crlList = new DssHelper().readCRLsFromCert((X509Certificate) certificateChain[0]);
	        byte[][] crls = new byte[crlList.size()][];
	        for (int i = 0 ; i < crlList.size();i++) {
				crls[i] = ( (X509CRL) crlList.get(i)).getEncoded();
			}
	        
	        Iterable<byte[]> certifiates = Arrays.asList(certs);
	        COSDictionary dss = new DssHelper().createDssDictionary(certifiates,Arrays.asList(crls) , null);
	        catalogDict.setItem(COSName.getPDFName("DSS"), dss);
	     // =========================== For LTV Enable ===========================

			doc.addSignature(signature, this);
			doc.saveIncremental(fos);

			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public byte[] sign(InputStream is) throws IOException {
		try {
			List<Certificate> certList = new ArrayList<>();
			certList.add(certificate);
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
			CMSSignedData signedData = gen.generate(msg, false);
			
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
	public static void signWithTSA(String passwordP12,String inputFileP12,String inputFileName,String outputFile,String filePath,String urlTsaClient ) throws IOException, GeneralSecurityException, SignatureException {
		char[] password = passwordP12.toCharArray();

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream(filePath + inputFileP12), password);

		Enumeration<String> aliases = keystore.aliases();
		String alias;
		if (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
		} else {
			throw new KeyStoreException("Keystore is empty");
		}
		privateKey = (PrivateKey) keystore.getKey(alias, password);
		certificateChain = keystore.getCertificateChain(keystore.aliases().nextElement());
		certificate = certificateChain[0];
		if(!urlTsaClient.isEmpty() && urlTsaClient != null){
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			tsaClient = new TSAClient(new URL(urlTsaClient), null,
					null, digest);
		}
		
		File inFile = new File(filePath + inputFileName);
		File outFile = new File(filePath + outputFile);
		new SignAndTimeStamp().signPdf(inFile, outFile);
	}
	
	private CMSSignedData signTimeStamps(CMSSignedData signedData)
            throws IOException, TSPException
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
            throws IOException, TSPException
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