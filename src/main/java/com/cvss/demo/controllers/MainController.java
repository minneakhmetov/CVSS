package com.cvss.demo.controllers;

import com.cvss.demo.lib.CvssV2;
import com.cvss.demo.model.ResponseModel;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class MainController {

    ModelMapper mapper = new ModelMapper();

    @GetMapping("/")
    public String getMainPage(){
        return "index";
    }

//    @PostMapping("/calculate")
//    @ResponseBody
//    public ResponseModel calculate(
//            @RequestParam("attackVector") String av,
//            @RequestParam("attackComplexity") String ac,
//            @RequestParam("authentication") String au,
//            @RequestParam("confidentiality") String c,
//            @RequestParam("integrity") String i,
//            @RequestParam("availability") String a
//    ){
//        return mapper.map(new CvssV2()
//                .attackVector(mapper.map(av, CvssV2.AttackVector.class))
//                .attackComplexity(mapper.map(ac, CvssV2.AttackComplexity.class))
//                .authentication(mapper.map(au, CvssV2.Authentication.class))
//                .confidentiality(mapper.map(c, CvssV2.CIA.class))
//                .integrity(mapper.map(i, CvssV2.CIA.class))
//                .availability(mapper.map(a, CvssV2.CIA.class))
//                .calculateScore(), ResponseModel.class);
//    }

    @PostMapping("/calculate")
    @ResponseBody
    public ResponseModel calculate(
            @RequestParam("attackVector") String av,
            @RequestParam("attackComplexity") String ac,
            @RequestParam("authentication") String au,
            @RequestParam("confidentiality") String c,
            @RequestParam("integrity") String i,
            @RequestParam("availability") String a,
            @RequestParam("exploitability") String e,
            @RequestParam("remediationLevel") String rl,
            @RequestParam("reportConfidence") String rc,
            @RequestParam("collateralDamagePotential") String cdp,
            @RequestParam("targetDistribution") String td,
            @RequestParam("confidentialityRequirement") String cr,
            @RequestParam("integrityRequirement ") String ir,
            @RequestParam("availabilityRequirement") String ar

    ){
        return mapper.map(new CvssV2()
                .attackVector(mapper.map(av, CvssV2.AttackVector.class))
                .attackComplexity(mapper.map(ac, CvssV2.AttackComplexity.class))
                .authentication(mapper.map(au, CvssV2.Authentication.class))
                .confidentiality(mapper.map(c, CvssV2.CIA.class))
                .integrity(mapper.map(i, CvssV2.CIA.class))
                .availability(mapper.map(a, CvssV2.CIA.class))
                .exploitability(mapper.map(e, CvssV2.Exploitability.class))
                .remediationLevel(mapper.map(rl, CvssV2.RemediationLevel.class))
                .reportConfidence(mapper.map(rc, CvssV2.ReportConfidence.class))
                .collateralDamagePotential(mapper.map(cdp, CvssV2.CollateralDamagePotential.class))
                .targetDistribution(mapper.map(td, CvssV2.TargetDistribution.class))
                .confidentialityRequirement(mapper.map(cr, CvssV2.CRIRAR.class))
                .integrityRequirement(mapper.map(ir, CvssV2.CRIRAR.class))
                .availabilityRequirement(mapper.map(ar, CvssV2.CRIRAR.class))
                .calculateScore(),
                ResponseModel.class);
    }
}
