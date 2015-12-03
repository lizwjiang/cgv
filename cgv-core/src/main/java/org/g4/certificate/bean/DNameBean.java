package org.g4.certificate.bean;

import java.io.Serializable;

/**
 * The bean class to store all the properties of dname
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class DNameBean implements Serializable {
    //0 : global, 1 : server, 2: client 3: none 4: CA
    private int type;
    private String organizationUnit;
    private String organization;
    private String city;
    private String province;
    private String countryCode;
    private String email;

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
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
}
