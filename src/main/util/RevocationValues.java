package main.util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.esf.OtherRevVals;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.CertificateList;

/**
 * <pre>
 * RevocationValues ::= SEQUENCE {
 *    crlVals [0] SEQUENCE OF CertificateList OPTIONAL,
 *    ocspVals [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
 *    otherRevVals [2] OtherRevVals OPTIONAL}
 * </pre>
 */
public class RevocationValues
    extends ASN1Object
{

    private ASN1Sequence crlVals;
    private ASN1Sequence ocspVals;
    private OtherRevVals otherRevVals;

    public RevocationValues(CertificateList[] crlVals,
                            OCSPResponse[] ocspVals, OtherRevVals otherRevVals)
    {
        if (null != crlVals)
        {
            this.crlVals = new DERSequence(crlVals);
        }
        if (null != ocspVals)
        {
            this.ocspVals = new DERSequence(ocspVals);
        }
        this.otherRevVals = otherRevVals;
    }

    public CertificateList[] getCrlVals()
    {
        if (null == this.crlVals)
        {
            return new CertificateList[0];
        }
        CertificateList[] result = new CertificateList[this.crlVals.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = CertificateList.getInstance(this.crlVals
                .getObjectAt(idx));
        }
        return result;
    }

    public OCSPResponse[] getOcspVals()
    {
        if (null == this.ocspVals)
        {
            return new OCSPResponse[0];
        }
        OCSPResponse[] result = new OCSPResponse[this.ocspVals.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = OCSPResponse.getInstance(this.ocspVals
                .getObjectAt(idx));
        }
        return result;
    }

    public OtherRevVals getOtherRevVals()
    {
        return this.otherRevVals;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (null != this.crlVals)
        {
            v.add(new DERTaggedObject(true, 0, this.crlVals));
        }
        if (null != this.ocspVals)
        {
            v.add(new DERTaggedObject(true, 1, this.ocspVals));
        }
        if (null != this.otherRevVals)
        {
            v.add(new DERTaggedObject(true, 2, this.otherRevVals.toASN1Primitive()));
        }
        return new DERSequence(v);
    }
}
