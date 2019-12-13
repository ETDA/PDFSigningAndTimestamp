package main;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

public class GetOcspResp {
	public OCSPResp getOcspResp(X509Certificate certificate, X509Certificate issuer)
			throws MalformedURLException, IOException, CertificateEncodingException, OperatorCreationException,
			OCSPException {

		Principal subjectX500Principal = certificate.getSubjectX500Principal();

		String ocspUrl = getOCSPUrl(certificate);
		if (ocspUrl == null) {
			System.out.println("OCSP URL for '" + subjectX500Principal + "' is empty");
			return null;
		}

		// Generate OCSP request
		OCSPReq ocspReq = generateOcspRequest(issuer, certificate.getSerialNumber());

		// Get OCSP response from server
		OCSPResp ocspResp = requestOCSPResponse(ocspUrl, ocspReq);
		
		return ocspResp;
	}

	private OCSPReq generateOcspRequest(X509Certificate issuerCert, BigInteger serialNumber)
			throws OCSPException, CertificateEncodingException, OperatorCreationException, IOException {

		BcDigestCalculatorProvider util = new BcDigestCalculatorProvider();

		// Generate the id for the certificate we are looking for
		CertificateID id = new CertificateID(util.get(CertificateID.HASH_SHA1),
				new X509CertificateHolder(issuerCert.getEncoded()), serialNumber);
		OCSPReqBuilder ocspGen = new OCSPReqBuilder();

		ocspGen.addRequest(id);

		BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
		Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true,
				new DEROctetString(nonce.toByteArray()));
		ocspGen.setRequestExtensions(new Extensions(new Extension[] { ext }));

		return ocspGen.build();
	}

	public OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq) throws IOException, MalformedURLException {
		byte[] bytes = ocspReq.getEncoded();
		HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
		connection.setRequestProperty("Content-Type", "application/ocsp-request");
		connection.setRequestProperty("Accept", "application/ocsp-response");
		connection.setDoOutput(true);
		DataOutputStream outputStream = new DataOutputStream(new BufferedOutputStream(connection.getOutputStream()));
		outputStream.write(bytes);
		outputStream.flush();
		outputStream.close();
		if (connection.getResponseCode() != 200) {
			// this.log.error("OCSP request has been failed (HTTP {}) - {}",
			// connection.getResponseCode(),
			// connection.getResponseMessage());
			System.out.println("OCSP request has been failed (HTTP {}) - {}" + connection.getResponseCode()
					+ connection.getResponseMessage());
		}
		try (InputStream in = (InputStream) connection.getContent()) {
			return new OCSPResp(in);
		}
	}

	@SuppressWarnings("resource")
	private String getOCSPUrl(X509Certificate certificate) throws IOException {
		byte[] obj;
		obj = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

		if (obj == null) {
			return null;
		}

		AuthorityInformationAccess authorityInformationAccess;
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(obj)).readObject());
		authorityInformationAccess = AuthorityInformationAccess
				.getInstance(new ASN1InputStream(oct.getOctets()).readObject());

		AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
		for (AccessDescription accessDescription : accessDescriptions) {
			boolean correctAccessMethod = accessDescription.getAccessMethod()
					.equals(X509ObjectIdentifiers.ocspAccessMethod);
			if (!correctAccessMethod) {
				continue;
			}

			GeneralName name = accessDescription.getAccessLocation();
			if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
				continue;
			}

			DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject) name.toASN1Primitive(), false);
			return derStr.getString();
		}

		return null;

	}
	
	@SuppressWarnings("resource") X509Certificate getIssuerCert(X509Certificate certificate) throws IOException {
		byte[] obj;
		obj = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

		if (obj == null) {
			return null;
		}

		AuthorityInformationAccess authorityInformationAccess;
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(obj)).readObject());
		authorityInformationAccess = AuthorityInformationAccess
				.getInstance(new ASN1InputStream(oct.getOctets()).readObject());

		AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
		for (AccessDescription accessDescription : accessDescriptions) {
			if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
		        GeneralName location = accessDescription.getAccessLocation();
		        if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
		            String issuerUrl = location.getName().toString();
		            // http URL to issuer (test in your browser to see if it's a valid certificate)
		            // you can use java.net.URL.openStream() to create a InputStream and create
		            // the certificate with your CertificateFactory
		            URL url = new URL(issuerUrl);
		            CertificateFactory certificateFactory;
		            X509Certificate issuer = null;
		            try {
		            	certificateFactory = CertificateFactory.getInstance("X.509");
						issuer = (X509Certificate) certificateFactory.generateCertificate(url.openStream());
						
					} catch (CertificateException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} 
		            return issuer;
		        }
		    }
		}

		return null;

	}
}
