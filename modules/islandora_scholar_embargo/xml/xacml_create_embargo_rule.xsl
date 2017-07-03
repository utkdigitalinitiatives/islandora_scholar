<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:ext-str="http://exslt.org/strings"
                xmlns:policy="urn:oasis:names:tc:xacml:1.0:policy"
                xmlns="urn:oasis:names:tc:xacml:1.0:policy"
                exclude-result-prefixes="xs ext-str policy"
                version="1.0">

    <xsl:output method="xml" indent="yes" encoding="UTF-8"/>
    <xsl:strip-space elements="*"/>

    <xsl:param name="users" select="''"/>
    <xsl:param name="dsids" select="''"/>

    <xsl:template match="@*|node()">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()"/>
        </xsl:copy>
    </xsl:template>

    <xsl:template match="text()">
        <xsl:value-of select="normalize-space(.)"/>
    </xsl:template>

    <xsl:template match="/policy:Policy/policy:Target[1]">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()"/>
        </xsl:copy>
        <xsl:call-template name="insert-deny-dsid-rule"/>
        <xsl:if test="count(/policy:Policy/policy:Rule) = 0">
            <xsl:call-template name="insert-allow-everything-else-rule"/>
        </xsl:if>
    </xsl:template>

    <xsl:template name="insert-deny-dsid-rule">
        <Rule RuleId="deny-dsid-mime" Effect="Deny">
            <Target>
                <Subjects>
                    <AnySubject/>
                </Subjects>
                <xsl:call-template name="insert-deny-dsid-rule-resources">
                    <xsl:with-param name="dsids-to-embargo" select="ext-str:tokenize($dsids, ',')"/>
                </xsl:call-template>

                <Actions>
                    <Action>
                        <ActionMatch MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                            <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">urn:fedora:names:fedora:2.1:action:id-getDatastreamDissemination</AttributeValue>
                            <ActionAttributeDesignator AttributeId="urn:fedora:names:fedora:2.1:action:id"
                                                       DataType="http://www.w3.org/2001/XMLSchema#string"/>
                        </ActionMatch>
                    </Action>
                </Actions>
            </Target>
            <Condition FunctionId="urn:oasis:names:tc:xacml:1.0:function:not">
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:or">
                    <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of">
                        <SubjectAttributeDesignator DataType="http://www.w3.org/2001/XMLSchema#string"
                                                    MustBePresent="false"
                                                    AttributeId="urn:fedora:names:fedora:2.1:subject:loginId"/>
                        <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-bag">
                            <xsl:for-each select="ext-str:tokenize($users, ',')">
                                <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">
                                    <xsl:value-of select="normalize-space(.)"/>
                                </AttributeValue>
                            </xsl:for-each>
                        </Apply>
                    </Apply>
                    <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of">
                        <SubjectAttributeDesignator DataType="http://www.w3.org/2001/XMLSchema#string"
                                                    MustBePresent="false" AttributeId="fedoraRole"/>
                        <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-bag">
                            <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">administrator</AttributeValue>
                        </Apply>
                    </Apply>
                </Apply>
            </Condition>
        </Rule>
    </xsl:template>

    <xsl:template name="insert-deny-dsid-rule-resources">
        <xsl:param name="dsids-to-embargo"/>
        <xsl:choose>
            <xsl:when test="count($dsids-to-embargo) = 0">
                <Resources>
                    <AnyResource/>
                </Resources>
            </xsl:when>
            <xsl:otherwise>
                <Resources>
                    <xsl:for-each select="$dsids-to-embargo">
                        <Resource>
                            <ResourceMatch MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                                <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">
                                    <xsl:value-of select="normalize-space(.)"/>
                                </AttributeValue>
                                <ResourceAttributeDesignator DataType="http://www.w3.org/2001/XMLSchema#string"
                                                             AttributeId="urn:fedora:names:fedora:2.1:resource:datastream:id"/>
                            </ResourceMatch>
                        </Resource>
                    </xsl:for-each>
                </Resources>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <xsl:template name="insert-allow-everything-else-rule">
        <Rule RuleId="allow-everything-else" Effect="Permit">
            <Target>
                <Subjects>
                    <AnySubject/>
                </Subjects>
                <Resources>
                    <AnyResource/>
                </Resources>
                <Actions>
                    <AnyAction/>
                </Actions>
            </Target>
        </Rule>
    </xsl:template>
</xsl:stylesheet>