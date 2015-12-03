package org.g4.certificate.bean;

import java.io.Serializable;

/**
 * This class is used to encapsulate all parameters of TSO certificate generation by Keytool or OpenSSL
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CertPropsBean implements Serializable {
    //0 : LB, 1 : Server, 2: Client, 3: CA
    private int type;
    private String clientFQDN;
    private String serverFQDN;
    private String caFQDN;
    private String organizationUnit;
    private String organization;
    private String city;
    private String province;
    private String countryCode;
    private String email;
    private boolean test = false;

    public int getType() {
        return type;
    }

    public String getCaFQDN() {
        return caFQDN;
    }

    public void setCaFQDN(String caFQDN) {
        this.caFQDN = caFQDN;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getClientFQDN() {
        return clientFQDN;
    }

    public void setClientFQDN(String clientFQDN) {
        this.clientFQDN = clientFQDN;
    }

    public String getServerFQDN() {
        return serverFQDN;
    }

    public void setServerFQDN(String serverFQDN) {
        this.serverFQDN = serverFQDN;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getProvince() {
        return province;
    }

    public void setProvince(String province) {
        this.province = province;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isTest() {
        return test;
    }

    public void setTest(boolean test) {
        this.test = test;
    }
}
