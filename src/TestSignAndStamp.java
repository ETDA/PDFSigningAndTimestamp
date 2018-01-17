

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SignatureException;

 

public class TestSignAndStamp {
	public static void main (String[]args)throws SignatureException, IOException, GeneralSecurityException {

		String passwordP12 = "P@ssw0rd";
		String inputFileP12 = "rndCodesigning.p12";
		String inputFileName = "pdfA3.pdf";
		String outputFile = "tsa_signed.pdf";
		String filePath = "D:/Users/Itsaya/workspace/PDFA3/";
//		String urlTsaClient = "http://10.2.9.27:8777/adss/tsa";
		String urlTsaClient = "";
		SignAndTimeStamp.signWithTSA(passwordP12, inputFileP12, inputFileName, outputFile, filePath, urlTsaClient);
		
		System.out.println("********Sign And TimeStamp Done**********");
	}

}
