package com.chendong.trustmanagement.runbody;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;

public class TrustServer {

    public static void main(String[] args) throws IOException {
        TrustServer ts = new TrustServer(0, 10, 0.8);
        ts.interaction();
        ts.getDomain(0).printNodeTrust();
    }

    final private int DOMAIN_NODE_NUMBER = 400;         //每个域中节点的数量
    private double MALICIOUS_NODE_RATIO = 0;            //恶意节点比例
    private double TRUST_FACTOR = 0.8;                  //信任衰减因子
    private int interactionTimes = 0;                   //交互次数

    int index = 100;
    double[] res = new double[index];
    public double[] getRes() {
        return res;
    }

    Domain[] domains = new Domain[2];       //设置域的数量

    public TrustServer(double MALICIOUS_NODE_RATIO, int interactionTimes, double TRUST_FACTOR) {
        this.MALICIOUS_NODE_RATIO = MALICIOUS_NODE_RATIO;
        this.TRUST_FACTOR = TRUST_FACTOR;
        this.interactionTimes = interactionTimes;
        initalDomain();
    }

//    初始化域
    public void initalDomain() {
        for(int index = 0; index < domains.length; index++) {
            domains[index] = new Domain(DOMAIN_NODE_NUMBER,TRUST_FACTOR,MALICIOUS_NODE_RATIO);
        }
    }

    public void setInteractionTimes(int interactionTimes) {
        this.interactionTimes = interactionTimes;
    }

//    开始交互函数
    public void interaction() {
        while(interactionTimes > 0) {
            for(Domain domian: domains) {
                domian.interaction();
            }

            crossDomainInteraction();

            for (int domainIndex = 0; domainIndex < domains.length; domainIndex++) {
                domains[domainIndex].addDomainTrust(domainTrustEvaluate(domainIndex));
            }

            interactionTimes--;
        }
    }

//    节点跨域交互处理
    public void crossDomainInteraction() {
        ArrayList<Node> domain1 = domains[0].getCrossDomainNodeList();
        ArrayList<Node> domain2 = domains[1].getCrossDomainNodeList();

        for(int index = 0; index < domain1.size(); ) {
            if (domain1.get(index).getNodeInteractionStatus()) {
                domain1.remove(index);
                continue;
            }

            index++;
        }

        for(int index = 0; index < domain2.size(); ) {
            if (domain2.get(index).getNodeInteractionStatus()) {
                domain1.remove(index);
                continue;
            }

            index++;
        }

        if (domain1.isEmpty() || domain2.isEmpty()) {
            return;
        } else {
            int index1 = 0;
            int index2 = 0;
            for(;index1 < domain1.size() && index2<domain2.size(); index1++, index2++) {
                domains[0].innerDomainInteraction(domain1.get(index1),domain2.get(index2));
            }
        }
    }

//    获取对应的域
    public Domain getDomain(int domainId) {
        return domains[domainId];
    }

//    域信任评估
    public double domainTrustEvaluate(int domainId) {
        double domainTrust = 0;
        double lambda1 = 0.6;
        double lambda2 = 0.4;

        ArrayList<Node> nodeArrayList = getDomain(domainId).getNodeList();

//        直接信任评估
        double directTrustEvaluate = 0;
        int directTrustNodeNumber = 0;

        double maxNodeTrustValue = 0;

        for (Node node : nodeArrayList) {
            if (node.getNodeTrust() > maxNodeTrustValue) {
                maxNodeTrustValue = node.getNodeTrust();
            }

            double singleNodeDirectTrustEvaluate = 0;
            LinkedHashSet<Node> nodeLinkedHashSet = node.getInteractionNodeSet();
            for (Node directInteractionNode : nodeLinkedHashSet) {
                singleNodeDirectTrustEvaluate = singleNodeDirectTrustEvaluate = directInteractionNode.getNodeTrust();
            }

            directTrustEvaluate = directTrustEvaluate + singleNodeDirectTrustEvaluate;
            directTrustNodeNumber++;
        }
        if (directTrustNodeNumber != 0) {
            directTrustEvaluate = directTrustEvaluate/directTrustNodeNumber;
        }

//        间接信任评估
        double indirectTrustEvaluate = 0;
        int indirectNodeNumber = 0;
        for (Node node : nodeArrayList) {
            double singleIndirectTrust = 0;
            LinkedHashSet<Node> nodeLinkedHashSet = node.getInteractionNodeSet();
            for (Node interactionNode : nodeLinkedHashSet) {
                singleIndirectTrust = singleIndirectTrust + interactionNode.getNodeTrust()/maxNodeTrustValue*
                        node.getNodeTrust();
            }
            singleIndirectTrust = singleIndirectTrust/nodeLinkedHashSet.size();

            indirectTrustEvaluate = indirectTrustEvaluate = singleIndirectTrust;
            indirectNodeNumber++;
        }
        indirectTrustEvaluate = indirectTrustEvaluate/indirectNodeNumber;

        domainTrust = lambda1*directTrustEvaluate + lambda2*indirectTrustEvaluate;

        return domainTrust;
    }
}

