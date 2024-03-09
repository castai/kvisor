eksctl utils associate-iam-oidc-provider --region=us-east-1 --cluster=am-kvisor-test --approve

eksctl create iamserviceaccount \
    --name ebs-csi-controller-sa \
    --namespace kube-system \
    --cluster am-kvisor-test \
    --role-name AmazonEKS_EBS_CSI_DriverRole \
    --region us-east-1 \
    --role-only \
    --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
    --approve

account_id=$(aws sts get-caller-identity --query "Account" --output text)

eksctl create addon --name aws-ebs-csi-driver --cluster am-kvisor-test --service-account-role-arn arn:aws:iam::028075177508:role/AmazonEKS_EBS_CSI_DriverRole --region us-east-1 --force
