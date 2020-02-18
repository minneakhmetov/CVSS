package com.cvss.demo.lib;

import lombok.Getter;
import lombok.Setter;

public class Score {

    private double baseScore;
    private double impactSubScore;
    private double exploitabilitySubScore;
    private double temporalScore;
    @Getter
    @Setter
    private double environmentalScore;

    public Score(double baseScore, double impactSubScore, double exploitabilitySubScore, double environmentalScore) {
        this(baseScore, impactSubScore, exploitabilitySubScore, -1, environmentalScore);
    }

    public Score(double baseScore, double impactSubScore, double exploitabilitySubScore, double temporalScore, double environmentalScore) {
        this.baseScore = baseScore;
        this.impactSubScore = impactSubScore;
        this.exploitabilitySubScore = exploitabilitySubScore;
        this.temporalScore = temporalScore;
        this.environmentalScore = environmentalScore;
    }

    /**
     * Returns the base score.
     * @return the base score
     */
    public double getBaseScore() {
        return baseScore;
    }

    /**
     * Returns the impact subscore.
     * @return the impact subscore
     */
    public double getImpactSubScore() {
        return impactSubScore;
    }

    /**
     * Returns the exploitability subscore.
     * @return the exploitability subscore
     */
    public double getExploitabilitySubScore() {
        return exploitabilitySubScore;
    }

    /**
     * Returns the temporal subscore.
     * @return the temporal subscore
     */
    public double getTemporalScore() {
        return temporalScore;
    }


}