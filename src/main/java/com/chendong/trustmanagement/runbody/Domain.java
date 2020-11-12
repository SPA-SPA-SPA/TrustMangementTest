package com.chendong.trustmanagement.runbody;

import org.springframework.web.util.pattern.PathPattern;

import java.io.IOException;
import java.lang.annotation.Documented;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;

public class Domain {
    public static void main(String[] args) throws IOException {
        Domain domain = new Domain(100,0.8,0);

        for (int index = 0; index < 100; index++) {
           domain.interaction();
           domain.printNodeTrust();
           System.out.println();
        }
    }

    private int domainId;
    private static int domainIdSet = 1;
    private double MALICIOUS_NODE_RATIO = 0;    //恶意节点比率
    private double TRUST_FACTOR = 0;             //信任衰减因子
    private int NODE_NUMBER = 0;                 //每个域的节点数量
    private static double NODE_INITAL_TRUST = 0.5;      //节点初始信任值设置

    private final int DOMAIN_AREA = 800;      //虚拟出整个域的大小,域的宽度和长度
    private final double NODE_FEEL_DISTANCE = 50;       //节点感知距离
    private final int NODE_RADIUS = 5;
    private final double MALICIOUS_NODE_THRESHOLD = 0.5;    //恶意节点信任阈值
    public final double LAMBDA = 0.8;                      //信任衰减因子

    private final double NODE_INTERACTION_THRESHOLD = 0.5;              //节点交互阈值
    private final double INNER_DOMAIN_INTERACTION_THRESHOLD = 0.9;      //节点域内交互阈值
    private final int MAX_INTERACTION_FIND_TIMES = 10;                  //最大交互查找次数

    ArrayList<Node> nodeList = new ArrayList<>();               //保存新生成的节点
    ArrayList<Node> badNodeList = new ArrayList<>();            //保存识别出的恶意节点
    ArrayList<Node> crossDomainNodeList = new ArrayList<>();    //保存跨域交互节点
    ArrayList<Double> domainTrustList = new ArrayList<>();      //保存域信任值变化情况

    public Domain(int NODE_NUMBER, double TRUST_FACTOR, double MALICIOUS_NODE_RATIO) {
        domainId = domainIdSet;
        domainIdSet++;

        this.NODE_NUMBER = NODE_NUMBER;
        this.TRUST_FACTOR = TRUST_FACTOR;
        this.MALICIOUS_NODE_RATIO = MALICIOUS_NODE_RATIO;

        createNode();
    }

//    参数设置
    public void parameterSetting(double MALICIOUS_NODE_RATIO, double TRUST_FACTOR) {
        this.MALICIOUS_NODE_RATIO = MALICIOUS_NODE_RATIO;
        this.TRUST_FACTOR = TRUST_FACTOR;

        setMaliciousNode();
    }

//    新建节点
    public void createNode() {
        for (int i = 0; i < NODE_NUMBER; i++) {
            Node node = new Node(NODE_INITAL_TRUST, DOMAIN_AREA, domainId);
            nodeList.add(node);
        }
    }

//    按比例设置恶意节点
    public void setMaliciousNode() {
        for (Node node : nodeList) {
            node.setNodeStatus(true);
        }

        Random random = new Random();
        int maliciousNodeNumber = (int)Math.floor(nodeList.size()*MALICIOUS_NODE_RATIO);
        while (maliciousNodeNumber > 0) {
            int nodeId = random.nextInt(nodeList.size());
            if (nodeList.get(nodeId).getNodeStatus()) {
                nodeList.get(nodeId).setNodeStatus(false);
                maliciousNodeNumber--;
            }
        }
    }

//    开始域内交互
    public void interaction() {
        Random random = new Random();

        crossDomainNodeList.clear();            //清空历史中的交互状态
        for (Node node : nodeList) {
            node.setNodeInteractionSet(false);
        }

        for (Node node : nodeList) {
            double nodeInteraction = random.nextDouble();
            if (nodeInteraction >= NODE_INTERACTION_THRESHOLD) {        //有意向交互
                double innerDomainInteraction = random.nextDouble();
                if (innerDomainInteraction <= INNER_DOMAIN_INTERACTION_THRESHOLD) {             //域内交互
                    int findTimes = 0;
                    while (findTimes < MAX_INTERACTION_FIND_TIMES) {
                        int targatNodeId = random.nextInt(nodeList.size());
                        if (!nodeList.get(targatNodeId).getNodeInteractionStatus()) {
                            innerDomainInteraction(nodeList.get(targatNodeId),node);
                            break;
                        }
                        findTimes++;
                    }
                } else {            //跨域交互
                    crossDomainInteraction(node);
                }
            }
        }
    }

//    域内交互处理
    public void innerDomainInteraction(Node sourceNode, Node targetNode) {
        sourceNode.setNodeInteractionSet(true);
        targetNode.setNodeInteractionSet(true);

        double trustEvaluate = nodeTrustEvaluate(targetNode);
        targetNode.addNodeTrustEvaluate(sourceNode,trustEvaluate);
    }

    //    生成指定参数的正态分布
    public double getNumberInNormalDistribution(double mean, double std_dev) {
        return mean + randomNormalDistribution()*std_dev;
    }

    //    随机数生成
    public double randomNormalDistribution() {
        double u, v, w, c;
        w = 0;

        do {
            u = Math.random()*2 - 1.0;
            v = Math.random()*2 - 1.0;
            w = u*u + v*v;
        }while (w == 0.0 || w>= 1.0);

        c = Math.sqrt((-2*Math.log(w))/w);
        return u*c;
    }

//    节点信任评估函数   函数运行有误，需要修改，增加修改节点信任值部分的内容
    public double nodeTrustEvaluate(Node node) {
        int nodeRealAbility = node.getNodeRealAbility();
        int nodeADAbility = node.getNodeADAbility();

        Random random = new Random();

        //        基于正态分布给出评分
        double nodeTrust = node.getNodeTrust();
        double score = 0;
        if (nodeRealAbility >= nodeADAbility) {
            score = 0;
            double set = random.nextDouble();
            if (set <= 0.99) {
                while ( score < nodeTrust || score > 1) {
                    score = getNumberInNormalDistribution(nodeTrust,nodeTrust);
                }
            } else {
                while (score < 0 || score > 1) {
                    score = getNumberInNormalDistribution(nodeTrust,nodeTrust);
                }
            }

        } else {
            double set = random.nextDouble();
            score = 0;
            if (set <= 0.8) {
                while ( score < 0 || score > nodeTrust) {
                    score = getNumberInNormalDistribution(nodeTrust,nodeTrust);
                }
            } else {
                while (score < 0 || score > 1) {
                    score = getNumberInNormalDistribution(nodeTrust,nodeTrust);
                }
            }
        }

        ArrayList<Double> trustList = node.getTrustList();

        score = 2*score - 1;        //使用 y = 2x - 1 将[0,1]转化为[-1,1];

        if (trustList.size() == 0) {
//            没有设置信任初始值时，添加初始信任值作为第一次评价的信任值
            node.addTrustList(NODE_INITAL_TRUST);   //trustList存储的信任值范围为[-1,1];
        }else {
            node.addTrustList(score);

            double rep1 = 0;
            double rep2 = 0;
            int index = 1;
            int length = trustList.size();
            for (double s:trustList) {
                rep1 = rep1 + s*Math.pow(LAMBDA,length - index);
                rep2 = rep2 + Math.pow(LAMBDA,length - index);
                index++;
            }

            score = rep1/(2 + rep2);
        }

        score = 0.5*score + 0.5;        //score范围为[-1,1]，使用函数 y = 0.5x + 0.5 转化为范围[0,1];

        node.setNodeTrust(score);   //更新节点信任值
        return score;       // 0<= score <= 1
    }

//    跨域交互处理
    public void crossDomainInteraction(Node node) {
        crossDomainNodeList.add(node);
    }

//    获得需要跨域交互的节点的列表
    public ArrayList<Node> getCrossDomainNodeList() {
        for(int index = 0; index < crossDomainNodeList.size();) {
            if (crossDomainNodeList.get(index).getNodeInteractionStatus()) {
                crossDomainNodeList.remove(index);
            } else {
                index++;
            }
        }

        return crossDomainNodeList;
    }

//    获取节点的历史评价值
    public ArrayList<Double> getNodeTrustList(int nodeId) {
        return nodeList.get(nodeId).getNodeTrustList();
    }

//    打印节点的信任值
    public void printNodeTrust() {
        for(Node node : nodeList) {
            System.out.print(node.getNodeTrust() + " ");
        }
    }

//    获取域中的节点列表
    public ArrayList<Node> getNodeList() {
        return nodeList;
    }

    public void addDomainTrust(double domainTrust) {
        domainTrustList.add(domainTrust);
    }

    public ArrayList<Double> getDomainTrustList() {
        return domainTrustList;
    }
}



