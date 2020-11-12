package com.chendong.trustmanagement.runbody;

import java.util.*;

public class Node {
    public static void main(String[] args) {

    }

    private int nodeId = 0;
    private static int nodeIdSet = 0;
    private int domainId = 0;
    private double nodeTrust = 0;      //节点信任值
    private boolean isGoodNode = true;   //判断节点是否是恶意的,默认为好节点true
    private boolean isInteraction = false;   //节点交互状态标识

    private double nodeLocationX = 0;       //节点在域中的位置，X坐标
    private double nodeLocationY = 0;       //节点在域中的位置，Y坐标
    private int nodeADAbility = 0;          //节点广告的能力

    ArrayList<Node> feelNodeList = null;                     //保存节点附近的节点
    ArrayList<Double> trustList = null;                      //保存节点历史交互信任评价分数, trustList存储的信任值范围为[-1,1];
    ArrayList<Double> nodeTrustList = null;                 //保存节点历史信任值，即信任变化过程
    LinkedHashSet<Node> interactionNodeSet = null;       //保存节点历史交互过的节点

    Random random = new Random();   //随机数生成函数

    public Node(double NODE_INITAL_TRUST, int DOMAIN_AREA, int domainId){
        this.nodeTrust = NODE_INITAL_TRUST;
        this.nodeId = nodeIdSet;
        nodeIdSet++;

        nodeLocationX = random.nextDouble()*800;
        nodeLocationY = random.nextDouble()*800;
        nodeADAbility = random.nextInt(100);

//        trustList = new ArrayList<>();
        nodeTrustList = new ArrayList<>();
        interactionNodeSet = new LinkedHashSet<>();
        feelNodeList = new ArrayList<>();
        trustList = new ArrayList<>();
    }

//    获取节点位置
    public double[] getNodeLoction() {
        double[] loction = {nodeLocationX, nodeLocationY};
        return loction;
    }

    public int getNodeId() {
        return nodeId;
    }

    public double getNodeTrust() {
        return nodeTrust;
    }

    public void setNodeTrust(double nodeTrust) {
        this.nodeTrust = nodeTrust;
    }

    public boolean getNodeStatus() {
        return isGoodNode;
    }

    public void setNodeStatus(boolean isGoodNode){
        this.isGoodNode = isGoodNode;

    }

    public boolean getNodeInteractionStatus() {
        return isInteraction;
    }

    public void setNodeInteractionSet(boolean newInteractionStatus){
        isInteraction = newInteractionStatus;
    }

    public int getNodeDomainId() {
        return domainId;
    }

    public void setNodeDomainId(int newDomainId) {
        domainId = newDomainId;
    }

    public ArrayList<Double> getNodeTrustList() {
        return nodeTrustList;
    }

//    新增对节点的信任评价
    public void addNodeTrustEvaluate(Node sourceNode, double trustValue) {
        interactionNodeSet.add(sourceNode);
        nodeTrustList.add(trustValue);
    }

    public ArrayList<Double> getTrustList() {
        return trustList;
    }

    public void addTrustList(double trust) {
        trustList.add(trust);
    }

    public ArrayList<Node> getFeelNodeList() {
        return feelNodeList;
    }

    public void addFeelNode(Node sourceNode) {
        feelNodeList.add(sourceNode);
    }

    public int getNodeRealAbility() {
        int realAbility = 0;

        if (isGoodNode) {
            realAbility = nodeADAbility;
        }else {
            double realRandom = random.nextDouble();

            if (realRandom <= 0.8) {
                realAbility = random.nextInt(nodeADAbility);
            } else {
                realAbility = random.nextInt(100);
            }
        }

        return realAbility;
    }

    public int getNodeADAbility() {
        return nodeADAbility;
    }

    public LinkedHashSet<Node> getInteractionNodeSet() {
        return interactionNodeSet;
    }
}

