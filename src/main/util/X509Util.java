package main.util;
import java.awt.RenderingHints.Key;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;


public class X509Util {

	public static X509Certificate X509FromToken(TimeStampToken token)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		
		Store cs = token.getCertificates();
		
		@SuppressWarnings("unchecked")
		ArrayList<X509CertificateHolder> c = (ArrayList<X509CertificateHolder>) cs.getMatches(null);
		X509Certificate[] certStore = new X509Certificate[c.size()];
		for (int i = 0; i < c.size(); i++) {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(c.get(i).getEncoded());
			X509Certificate certTemp = (X509Certificate) certFactory.generateCertificate(in);

			certStore[i] = certTemp;
		}
		X509Certificate[] orderedStore = SortX509Chain(certStore);
		X509Certificate cert = orderedStore[0];

		if (cert == null) {
			return null;
		}
		return cert;
	}

	public static X509Certificate[] SortX509Chain(X509Certificate[] chain) {
		if (!chain[0].getSubjectDN().equals(chain[0].getIssuerDN())) {
			return chain;
		}
		int chainLenght = chain.length;
		X509Certificate[] newChain = new X509Certificate[chainLenght];
		boolean foundRoot = false;
		HashMap<X500Principal, X509Certificate> certMap = new HashMap<>();

		for (int i = 0; i < chainLenght; i++) {
			X500Principal issuer = chain[i].getIssuerX500Principal();
			X500Principal subject = chain[i].getSubjectX500Principal();
			certMap.put(issuer, chain[i]);
			if (issuer.equals(subject)) {
				newChain[chainLenght - 1] = chain[i];
				foundRoot = true;
			}
		}
		if (!foundRoot)
			return chain;

		for (int i = chainLenght - 2; i >= 0; i--) {
			newChain[i] = certMap.get(newChain[i + 1].getSubjectX500Principal());
		}

		return newChain;
	}
	
	public static List<X509Certificate> SortX509Chain(List<X509Certificate> chain) {

		List<X509Certificate> sorted = new ArrayList<>();
		
		X509Certificate[] chainArr = new X509Certificate[chain.size()];
		chainArr = chain.toArray(chainArr);
		
		X509Certificate[] sortedChain = SortX509Chain(chainArr);
		sorted = Arrays.asList(sortedChain);
		
		return sorted;
	}
	
	public static Certificate[] SortX509Chain(Certificate[] certificateChain, Certificate signerCert) {
        
		X509Certificate signCertificate = (X509Certificate) signerCert;	        
        List<X509Certificate> unsorted = new ArrayList<X509Certificate>(); 

		
        for(int i =0;i<certificateChain.length;i++){
        	
        	X509Certificate currentX509cert = (X509Certificate) certificateChain[i];	
        	unsorted.add(currentX509cert);
        }
        
        List<X509Certificate> X509Sorted = SortX509Chain(unsorted,signCertificate);
        Certificate[] certSorted = new Certificate[certificateChain.length];
        
        for(int i =0;i<certificateChain.length;i++){
        	
        	certSorted[i] = (Certificate) X509Sorted.get(i);
        }
        
        return certSorted;
	}
	
	public static List<X509Certificate> SortX509Chain(List<X509Certificate> chain, X509Certificate signerCert) {
		List<X509Certificate> sorted = new ArrayList<>();
		sorted.add(signerCert);
		X509Certificate cert = signerCert;
		
		for(int i=0; i<chain.size()-1; i++) {
			X500Principal issuer = cert.getIssuerX500Principal();
			X500Principal subject = cert.getSubjectX500Principal();
			// If last cert in sorted chain is root, sorting is done
			if(!issuer.equals(subject)) {
				for(int j=0; j<chain.size(); j++) {
					X509Certificate issuerCert = chain.get(j);
					X500Principal subjectOfIssuer = issuerCert.getSubjectX500Principal();
					if(issuer.equals(subjectOfIssuer)) {
						sorted.add(issuerCert);
						cert = issuerCert;
					}
				}
			}
		}
		return sorted;
	}
}

