package com.chendong.trustmanagement;

import com.chendong.trustmanagement.runbody.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;

@Controller
@RequestMapping("/")
public class HomeController {
    private static double MALICIOUS_RATIO = 0;                  //恶意节点比例
    private static int interactionTimes = 0;                    //交互次数
    private static double TRUST_FACTOR = 0.8;                   //信任衰减因子
    private static boolean isFirstRun = true;                  //标记运行次数

    private TrustServer ts = null;                              //信任服务器

    ArrayList<Node> nodeArrayList = null;                       //节点列表

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @RequestMapping(path = "/setting", method = RequestMethod.POST)
    @ResponseBody
    public String setting(@RequestParam(value = "maliciousRatio") double maliciousRatio,
                          @RequestParam(value = "interactionTimes") int interactionTimes,
                          @RequestParam(value = "trustFactor") double trustFactor) {
        System.out.println("path:/setting");

//        System.out.println(trustFactor);
//        System.out.println(interactionTimes);
//        System.out.println(maliciousRatio);

        if (interactionTimes != 0) {
            this.MALICIOUS_RATIO = maliciousRatio;
            this.interactionTimes = interactionTimes;
            this.TRUST_FACTOR = trustFactor;

            boolean runResult = runSystem(MALICIOUS_RATIO, interactionTimes, TRUST_FACTOR, isFirstRun);
            isFirstRun = false;

            if (runResult) {
                return "Success";
            }else {
                return "fail";
            }
        }else {
            return "fail";
        }
    }

    @RequestMapping(path = "/stopExpriment", method = RequestMethod.POST)
    @ResponseBody
    public String stopExpriment(@RequestParam(value = "isRuning") boolean isRuning) {
        System.out.println("/stopExpriment");

        if (isRuning == false) {
            return "运行已暂停";
        }else {
            return "暂停失败";
        }
    }

    @RequestMapping(path = "/searchNode", method = RequestMethod.POST)
    @ResponseBody
    public double[] searchNode(int nodeNumber) {
        System.out.println("/searchNode");

        if (isFirstRun) {
            return null;
        }

        ArrayList<Double> nodeTrustList = ts.getDomain(0).getNodeTrustList(nodeNumber);
        ArrayList<Double> domainTrustList = ts.getDomain(1).getDomainTrustList();

        double res[] = new double[nodeTrustList.size() + domainTrustList.size() + 1];
        res[0] = nodeTrustList.size();
        int index = 1;
        for (; index < res.length && index < nodeTrustList.size(); index++) {
            res[index] = nodeTrustList.get(index);
        }

        for (; index < res.length && index < domainTrustList.size(); index++) {
            res[index] = domainTrustList.get(index);
        }

        return res;
    }

//    系统运行设置
    public boolean runSystem(double maliciousRatio, int interactionTimes, double trustFactor, boolean isFirstRun) {
        if (isFirstRun) {
            ts = new TrustServer(MALICIOUS_RATIO,interactionTimes,trustFactor);
            ts.interaction();
        } else {
            ts.setInteractionTimes(interactionTimes);
            ts.interaction();
            System.out.println("run");
        }

        return true;
    }
}
