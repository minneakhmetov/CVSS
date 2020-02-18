package com.cvss.demo.model;

import lombok.Data;

@Data
public class RequestModel {

    private String attackVector;
    private String attackComplexity;
    private String authentication;
    private String confidentiality;
    private String integrity;
    private String availability;
    private String exploitability;
    private String remediationLevel;
    private String reportConfidence;

}
