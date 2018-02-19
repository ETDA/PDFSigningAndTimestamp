package main;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;

import sun.security.provider.certpath.ldap.LDAPCertStoreHelper;
import sun.security.x509.CRLDistributionPointsExtension;
import sun.security.x509.DistributionPoint;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.GeneralNames;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;


public class DssHelper {

	public DssHelper() {

	}

	public COSDictionary createDssDictionary(Iterable<byte[]> certifiates, Iterable<byte[]> crls, Iterable<byte[]> ocspResponses) throws IOException
	{
	    final COSDictionary dssDictionary = new COSDictionary();
	    dssDictionary.setNeedToBeUpdated(true);
	    dssDictionary.setName(COSName.TYPE, "DSS");

	    if (certifiates != null)
	        dssDictionary.setItem(COSName.getPDFName("Certs"), createArray(certifiates));
	    if (crls != null)
	        dssDictionary.setItem(COSName.getPDFName("CRLs"), createArray(crls));
	    if (ocspResponses != null)
	        dssDictionary.setItem(COSName.getPDFName("OCSPs"), createArray(ocspResponses));

	    return dssDictionary;
	}

	public COSArray createArray(Iterable<byte[]> datas) throws IOException
	{
	    COSArray array = new COSArray();
	    array.setNeedToBeUpdated(true);

	    if (datas != null)
	    {
	        for (byte[] data: datas)
	            array.add(createStream(data));
	    }

	    return array;
	}

	public COSStream createStream(byte[] data) throws IOException {
		//RandomAccessBuffer storage = new RandomAccessBuffer();
		COSStream stream = new COSStream();
		stream.setNeedToBeUpdated(true);
		final OutputStream unfilteredStream = stream.createRawOutputStream();
		unfilteredStream.write(data);
		unfilteredStream.flush();
		unfilteredStream.close();
		return stream;
	}
	
	public List<CRL> readCRLsFromCert(X509Certificate cert)
	        throws Exception {
	    List<CRL> crls = new ArrayList<>();
	    CRLDistributionPointsExtension ext =
	            X509CertImpl.toImpl(cert).getCRLDistributionPointsExtension();
	    if (ext == null) return crls;
	    
	    for (DistributionPoint o: (List<DistributionPoint>)
	            ext.get(CRLDistributionPointsExtension.POINTS)) {
	        GeneralNames names = o.getFullName();
	        if (names != null) {
	            for (GeneralName name: names.names()) {
	                if (name.getType() == GeneralNameInterface.NAME_URI) {
	                    URIName uriName = (URIName)name.getName();
	                    for (CRL crl: loadCRLs(uriName.getName())) {
	                        if (crl instanceof X509CRL) {
	                        	crls.add((X509CRL)crl);
	                        }
	                    }
	                    break;  // Different name should point to same CRL
	                }
	            }
	        }
	    }
	    return crls;
	}
	
	public Collection<? extends CRL> loadCRLs(String src) throws Exception { 
        InputStream in = null; 
        URI uri = null; 
        if (src == null) { 
            in = System.in; 
        } else { 
            try { 
                uri = new URI(src); 
                if (uri.getScheme().equals("ldap")) { 
                    // No input stream for LDAP 
                } else { 
                    in = uri.toURL().openStream(); 
                } 
            } catch (Exception e) { 
                try { 
                    in = new FileInputStream(src); 
                } catch (Exception e2) { 
                    if (uri == null || uri.getScheme() == null) { 
                        throw e2;   // More likely a bare file path 
                    } else { 
                        throw e;    // More likely a protocol or network problem 
                    } 
                } 
            } 
        } 
        if (in != null) { 
            try { 
                // Read the full stream before feeding to X509Factory, 
                // otherwise, keytool -gencrl | keytool -printcrl 
                // might not work properly, since -gencrl is slow 
                // and there's no data in the pipe at the beginning. 
                ByteArrayOutputStream bout = new ByteArrayOutputStream(); 
                byte[] b = new byte[4096]; 
                while (true) { 
                    int len = in.read(b); 
                    if (len < 0) break; 
                    bout.write(b, 0, len); 
                } 
                return CertificateFactory.getInstance("X509").generateCRLs( 
                        new ByteArrayInputStream(bout.toByteArray())); 
            } finally { 
                if (in != System.in) { 
                    in.close(); 
                } 
            } 
        } else {    // must be LDAP, and uri is not null 
            String path = uri.getPath(); 
            if (path.charAt(0) == '/') path = path.substring(1); 
            LDAPCertStoreHelper h = new LDAPCertStoreHelper(); 
            CertStore s = h.getCertStore(uri); 
            X509CRLSelector sel = 
                    h.wrap(new X509CRLSelector(), null, path); 
            return s.getCRLs(sel); 
        } 
    } 
}
