<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:ext-str="http://exslt.org/strings"
                xmlns:policy="urn:oasis:names:tc:xacml:1.0:policy"
                xmlns="urn:oasis:names:tc:xacml:1.0:policy"
                exclude-result-prefixes="xs ext-str policy"
                version="1.0">

    <xsl:output method="xml" indent="yes" encoding="UTF-8"/>
    <xsl:strip-space elements="*"/>

    <xsl:template match="@*|node()">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()"/>
        </xsl:copy>
    </xsl:template>

    <xsl:template match="policy:Rule[@RuleId='deny-dsid-mime'][@Effect='Deny']"/>

</xsl:stylesheet>