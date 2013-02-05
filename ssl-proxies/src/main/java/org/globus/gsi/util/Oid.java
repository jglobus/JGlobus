package org.globus.gsi.util;

/**
 * Common OID values.
 *
 * Adapted from BouncyCastle.
 */
public enum Oid
{
    /**
     * country code - StringType(SIZE(2))
     */
    C("2.5.4.6"),

    /**
     * organization - StringType(SIZE(1..64))
     */
    O("2.5.4.10"),

    /**
     * organizational unit name - StringType(SIZE(1..64))
     */
    OU("2.5.4.11"),

    /**
     * Title
     */
    T("2.5.4.12"),

    /**
     * common name - StringType(SIZE(1..64))
     */
    CN("2.5.4.3"),

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    SERIALNUMBER("2.5.4.5"),

    /**
    * locality name - StringType(SIZE(1..64))
    */
    L("2.5.4.7"),

    /**
    * state, or province name - StringType(SIZE(1..64))
    */
    ST("2.5.4.8"),

    /**
     * street - StringType(SIZE(1..64))
     */
    STREET("2.5.4.9"),

    /**
     * Naming attributes of type X520name
     */
    SURNAME("2.5.4.4"),
    GIVENNAME("2.5.4.42"),
    INITIALS("2.5.4.43"),
    GENERATION("2.5.4.44"),
    UNIQUE_IDENTIFIER("2.5.4.45"),

    /**
     * businessCategory - DirectoryString(SIZE(1..128)
     */
    BUSINESS_CATEGORY("2.5.4.15"),

    /**
     * postalCode - DirectoryString(SIZE(1..40)
     */
    POSTAL_CODE("2.5.4.17"),

    /**
     * dnQualifier - DirectoryString(SIZE(1..64)
     */
    DN_QUALIFIER("2.5.4.46"),

    /**
     * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
     */
    PSEUDONYM("2.5.4.65"),


    /**
     * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
     */
    DATE_OF_BIRTH("1.3.6.1.5.5.7.9.1"),

    /**
     * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
     */
    PLACE_OF_BIRTH("1.3.6.1.5.5.7.9.2"),

    /**
     * RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
     */
    GENDER("1.3.6.1.5.5.7.9.3"),

    /**
     * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
     * codes only
     */
    COUNTRY_OF_CITIZENSHIP("1.3.6.1.5.5.7.9.4"),

    /**
     * RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
     * codes only
     */
    COUNTRY_OF_RESIDENCE("1.3.6.1.5.5.7.9.5"),


    /**
     * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
     */
    NAME_AT_BIRTH("1.3.36.8.3.14"),

    /**
     * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
     * DirectoryString(SIZE(1..30))
     */
    POSTAL_ADDRESS("2.5.4.16"),

    /**
     * RFC 2256 dmdName
     */
    DMD_NAME("2.5.4.54"),

    /**
     * id-at-telephoneNumber
     */
    TELEPHONE_NUMBER("2.5.4.20"),

    /**
     * id-at-name
     */
    NAME("2.5.4.41"),

    /**
     * Email address (RSA PKCS#9 extension) - IA5String.
     * <p>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
     */
    EmailAddress("1.2.840.113549.1.9.1"),

    /**
     * more from PKCS#9
     */
    UnstructuredName("1.2.840.113549.1.9.2"),
    UnstructuredAddress("1.2.840.113549.1.9.8"),

    /*
    * others...
    */
    DC("0.9.2342.19200300.100.1.25"),

    /**
     * LDAP User id.
     */
    UID("0.9.2342.19200300.100.1.1"),

    IP("1.3.6.1.4.1.42.2.11.2.1");

    public final String oid;

    private Oid(String value)
    {
        this.oid = value;
    }

    @Override
    public String toString()
    {
        return oid;
    }
}
