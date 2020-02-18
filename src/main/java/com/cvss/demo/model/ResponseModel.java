package com.cvss.demo.model;

import lombok.Data;

@Data
public class ResponseModel {

    private Double baseScore;
    private Double impactSubScore;
    private Double exploitabilitySubScore;

}
