// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
import {EIP712} from "./EIP712.sol";
import {Payment} from "./Payment.sol";
contract BlueprintCore is EIP712, Payment {
    enum Status {Init, Issued, Pickup, Deploying, Deployed, GeneratedProof}
    struct DeploymentStatus {
        Status status;
        address deployWorkerAddr;
    }
    uint256 public totalProposalRequest;
    uint256 public totalDeploymentRequest;
    mapping(address => bytes32) public latestProposalRequestID;
    mapping(address => bytes32) public latestDeploymentRequestID;
    mapping(address => bytes32) public latestProjectID;
    mapping(address => uint256) public solverReputation;
    mapping(address => uint256) public workerReputation;
    mapping(bytes32 => DeploymentStatus) public requestDeploymentStatus;
    mapping(bytes32 => string) private deploymentProof;
    mapping(bytes32 => address) private requestSolver;
    mapping(bytes32 => address) private requestWorker;
    mapping(bytes32 => address) private projectIDs;
    struct Project {
        bytes32 id;
        bytes32 requestProposalID;
        bytes32 requestDeploymentID;
        address proposedSolverAddr;
    }
    address public constant dummyAddress = address(0);
    mapping(bytes32 => Project) private projects;
    mapping(bytes32 => bytes32[]) public deploymentIdList;
    address[] private workerAddresses;
    mapping(address => bytes) private workersPublicKey;
    mapping(string => address[]) private workerAddressesMp;
    string private constant WORKER_ADDRESS_KEY = "worker_address_key";
    mapping(uint256 => Status) public nftTokenIdMap;
    address public nftContractAddress;
    mapping(address => Status) public whitelistUsers;
    mapping(bytes32 => address) private deploymentOwners;
    string public constant PAYMENT_KEY = "payment_key";
    string public constant CREATE_AGENT_OP = "create_agent";
    string public constant UPDATE_AGENT_OP = "update_agent";
    address public feeCollectionWalletAddress;
    mapping(string => address[]) public paymentAddressesMp;
    mapping(address => bool) public paymentAddressEnableMp;
    mapping(address => mapping(string => uint256)) public paymentOpCostMp;
    mapping(address => mapping(address => uint256)) public userTopUpMp;
    event CreateProjectID(bytes32 indexed projectID, address walletAddress);
    event RequestProposal(
        bytes32 indexed projectID,
        address walletAddress,
        bytes32 indexed requestID,
        string base64RecParam,
        string serverURL
    );
    event RequestPrivateProposal(
        bytes32 indexed projectID,
        address walletAddress,
        address privateSolverAddress,
        bytes32 indexed requestID,
        string base64RecParam,
        string serverURL
    );
    event RequestDeployment(
        bytes32 indexed projectID,
        address walletAddress,
        address solverAddress,
        bytes32 indexed requestID,
        string base64Proposal,
        string serverURL
    );
    event RequestPrivateDeployment(
        bytes32 indexed projectID,
        address walletAddress,
        address privateWorkerAddress,
        address solverAddress,
        bytes32 indexed requestID,
        string base64Proposal,
        string serverURL
    );
    event AcceptDeployment(bytes32 indexed projectID, bytes32 indexed requestID, address indexed workerAddress);
    event GeneratedProofOfDeployment(
        bytes32 indexed projectID, bytes32 indexed requestID, string base64DeploymentProof
    );
    event UpdateDeploymentConfig(
        bytes32 indexed projectID, bytes32 indexed requestID, address workerAddress, string base64Config
    );
    event CreateAgent(
        bytes32 indexed projectID, bytes32 indexed requestID, address walletAddress, uint256 nftTokenId, uint256 amount
    );
    event UserTopUp(
        address indexed walletAddress, address feeCollectionWalletAddress, address tokenAddress, uint256 amount
    );
    modifier newProject(bytes32 projectId) {
        require(projects[projectId].id == 0, "projectId already exists");
        _;
    }
    modifier hasProjectNew(bytes32 projectId) {
        require(projects[projectId].id != 0, "projectId does not exist");
        _;
    }
    modifier hasProject(bytes32 projectId) {
        require(projects[projectId].id != 0 || projectIDs[projectId] != dummyAddress, "projectId does not exist");
        _;
    }
    function setProjectId(bytes32 projectId, address userAddr) internal newProject(projectId) {
        require(userAddr != dummyAddress, "Invalid userAddr");
        Project memory project =
            Project({id: projectId, requestProposalID: 0, requestDeploymentID: 0, proposedSolverAddr: dummyAddress});
        projects[projectId] = project;
        latestProjectID[userAddr] = projectId;
        emit CreateProjectID(projectId, userAddr);
    }
    function createProjectID() public returns (bytes32 projectId) {
        projectId = keccak256(abi.encodePacked(block.timestamp, msg.sender, block.chainid));
        setProjectId(projectId, msg.sender);
    }
    function upgradeProject(bytes32 projectId) public hasProject(projectId) {
        projects[projectId].requestProposalID = 0;
        projects[projectId].requestDeploymentID = 0;
        projects[projectId].proposedSolverAddr = dummyAddress;
    }
    function proposalRequest(
        address userAddress,
        bytes32 projectId,
        address solverAddress,
        string memory base64RecParam,
        string memory serverURL
    ) internal hasProject(projectId) returns (bytes32 requestID) {
        require(bytes(serverURL).length > 0, "serverURL is empty");
        require(bytes(base64RecParam).length > 0, "base64RecParam is empty");
        requestID = keccak256(abi.encodePacked(block.timestamp, userAddress, base64RecParam, block.chainid));
        require(projects[projectId].requestProposalID == 0, "proposal requestID already exists");
        latestProposalRequestID[userAddress] = requestID;
        projects[projectId].requestProposalID = requestID;
        totalProposalRequest++;
        if (solverAddress != dummyAddress) {
            requestSolver[requestID] = solverAddress;
        }
    }
    function createCommonProposalRequest(
        address userAddress,
        bytes32 projectId,
        string memory base64RecParam,
        string memory serverURL
    ) internal returns (bytes32 requestID) {
        requestID = proposalRequest(userAddress, projectId, dummyAddress, base64RecParam, serverURL);
        emit RequestProposal(projectId, userAddress, requestID, base64RecParam, serverURL);
    }
    function createProjectIDAndProposalRequest(bytes32 projectId, string memory base64RecParam, string memory serverURL)
        public
        returns (bytes32 requestID)
    {
        setProjectId(projectId, msg.sender);
        requestID = createCommonProposalRequest(msg.sender, projectId, base64RecParam, serverURL);
    }
    function createProjectIDAndProposalRequestWithSig(
        bytes32 projectId,
        string memory base64RecParam,
        string memory serverURL,
        bytes memory signature
    ) public returns (bytes32 requestID) {
        bytes32 digest = getRequestProposalDigest(projectId, base64RecParam, serverURL);
        address signerAddr = getSignerAddress(digest, signature);
        setProjectId(projectId, signerAddr);
        requestID = createCommonProposalRequest(signerAddr, projectId, base64RecParam, serverURL);
    }
    function deploymentRequest(
        address userAddress,
        bytes32 projectId,
        address solverAddress,
        address workerAddress,
        string memory base64Proposal,
        string memory serverURL,
        uint256 index
    ) internal hasProject(projectId) returns (bytes32 requestID, bytes32 projectDeploymentId) {
        require(bytes(serverURL).length > 0, "serverURL is empty");
        require(bytes(base64Proposal).length > 0, "base64Proposal is empty");
        projectDeploymentId =
            keccak256(abi.encodePacked(block.timestamp, userAddress, base64Proposal, block.chainid, projectId));
        require(projects[projectId].requestDeploymentID == 0, "deployment requestID already exists");
        requestID =
            keccak256(abi.encodePacked(block.timestamp, userAddress, base64Proposal, block.chainid, projectId, index));
        latestDeploymentRequestID[userAddress] = requestID;
        DeploymentStatus memory deploymentStatus = DeploymentStatus({
            status: (workerAddress == dummyAddress ? Status.Issued : Status.Pickup),
            deployWorkerAddr: workerAddress
        });
        requestDeploymentStatus[requestID] = deploymentStatus;
        projects[projectId].proposedSolverAddr = solverAddress;
    }
    function createCommonDeploymentRequest(
        address userAddress,
        bytes32 projectId,
        address solverAddress,
        address workerAddress,
        string memory base64Proposal,
        string memory serverURL
    ) internal returns (bytes32 requestID) {
        require(solverAddress != dummyAddress, "solverAddress is not valid");
        bytes32 projectDeploymentId;
        (requestID, projectDeploymentId) =
            deploymentRequest(userAddress, projectId, solverAddress, workerAddress, base64Proposal, serverURL, 0);
        totalDeploymentRequest++;
        projects[projectId].requestDeploymentID = projectDeploymentId;
        deploymentIdList[projectDeploymentId].push(requestID);
        if (workerAddress == dummyAddress) {
            emit RequestDeployment(projectId, userAddress, solverAddress, requestID, base64Proposal, serverURL);
        } else {
            emit RequestPrivateDeployment(
                projectId, userAddress, workerAddress, solverAddress, requestID, base64Proposal, serverURL
            );
            emit AcceptDeployment(projectId, requestID, workerAddress);
        }
    }
    function createCommonProjectIDAndDeploymentRequest(
        address userAddress,
        bytes32 projectId,
        string memory base64Proposal,
        address workerAddress,
        string memory serverURL
    ) internal returns (bytes32 requestID) {
        setProjectId(projectId, userAddress);
        bytes32 projectDeploymentId;
        (requestID, projectDeploymentId) =
            deploymentRequest(userAddress, projectId, dummyAddress, workerAddress, base64Proposal, serverURL, 0);
        totalDeploymentRequest++;
        projects[projectId].requestDeploymentID = projectDeploymentId;
        deploymentIdList[projectDeploymentId].push(requestID);
        if (workerAddress == dummyAddress) {
            emit RequestDeployment(projectId, userAddress, dummyAddress, requestID, base64Proposal, serverURL);
        } else {
            emit RequestPrivateDeployment(
                projectId, userAddress, workerAddress, dummyAddress, requestID, base64Proposal, serverURL
            );
            emit AcceptDeployment(projectId, requestID, workerAddress);
        }
    }
    function createProjectIDAndDeploymentRequest(
        bytes32 projectId,
        string memory base64Proposal,
        string memory serverURL
    ) public returns (bytes32 requestID) {
        requestID =
            createCommonProjectIDAndDeploymentRequest(msg.sender, projectId, base64Proposal, dummyAddress, serverURL);
    }
    function createProjectIDAndDeploymentRequestWithSig(
        bytes32 projectId,
        string memory base64Proposal,
        string memory serverURL,
        bytes memory signature
    ) public returns (bytes32 requestID) {
        bytes32 digest = getRequestDeploymentDigest(projectId, base64Proposal, serverURL);
        address signerAddr = getSignerAddress(digest, signature);
        requestID =
            createCommonProjectIDAndDeploymentRequest(signerAddr, projectId, base64Proposal, dummyAddress, serverURL);
    }
    function createProjectIDAndPrivateDeploymentRequest(
        bytes32 projectId,
        string memory base64Proposal,
        address privateWorkerAddress,
        string memory serverURL
    ) public returns (bytes32 requestID) {
        requestID = createCommonProjectIDAndDeploymentRequest(
            msg.sender, projectId, base64Proposal, privateWorkerAddress, serverURL
        );
    }
    function createAgent(
        address userAddress,
        bytes32 projectId,
        string memory base64Proposal,
        address privateWorkerAddress,
        string memory serverURL,
        uint256 tokenId,
        address tokenAddress
    ) internal returns (bytes32 requestID) {
        if (tokenAddress == address(0)) {
            require(nftTokenIdMap[tokenId] != Status.Pickup, "NFT token id already used");
            require(checkNFTOwnership(nftContractAddress, tokenId, userAddress), "NFT token not owned by user");
            requestID = createCommonProjectIDAndDeploymentRequest(
                userAddress, projectId, base64Proposal, privateWorkerAddress, serverURL
            );
            nftTokenIdMap[tokenId] = Status.Pickup;
            deploymentOwners[requestID] = userAddress;
            emit CreateAgent(projectId, requestID, userAddress, tokenId, 0);
        } else {
            require(paymentAddressEnableMp[tokenAddress], "Token address is invalid");
            uint256 cost = paymentOpCostMp[tokenAddress][CREATE_AGENT_OP];
            if (cost > 0) {
                payWithERC20(tokenAddress, cost, userAddress, feeCollectionWalletAddress);
            }
            requestID = createCommonProjectIDAndDeploymentRequest(
                userAddress, projectId, base64Proposal, privateWorkerAddress, serverURL
            );
            deploymentOwners[requestID] = userAddress;
            emit CreateAgent(projectId, requestID, userAddress, tokenId, cost);
        }
    }
    function createAgentWithToken(
        bytes32 projectId,
        string memory base64Proposal,
        address privateWorkerAddress,
        string memory serverURL,
        address tokenAddress
    ) public returns (bytes32 requestID) {
        require(tokenAddress != address(0), "Token address is empty");
        requestID = createAgent(msg.sender, projectId, base64Proposal, privateWorkerAddress, serverURL, 0, tokenAddress);
    }
    function createAgentWithTokenWithSig(
        bytes32 projectId,
        string memory base64Proposal,
        address privateWorkerAddress,
        string memory serverURL,
        address tokenAddress,
        bytes memory signature
    ) public returns (bytes32 requestID) {
        require(tokenAddress != address(0), "Token address is empty");
        bytes32 digest = getRequestDeploymentDigest(projectId, base64Proposal, serverURL);
        address signerAddr = getSignerAddress(digest, signature);
        requestID = createAgent(signerAddr, projectId, base64Proposal, privateWorkerAddress, serverURL, 0, tokenAddress);
    }
    function createAgentWithNFT(
        bytes32 projectId,
        string memory base64Proposal,
        address privateWorkerAddress,
        string memory serverURL,
        uint256 tokenId
    ) public returns (bytes32 requestID) {
        requestID =
            createAgent(msg.sender, projectId, base64Proposal, privateWorkerAddress, serverURL, tokenId, address(0));
    }
    function createAgentWithWhitelistUsers(
        bytes32 projectId,
        string memory base64Proposal,
        address privateWorkerAddress,
        string memory serverURL,
        uint256 tokenId
    ) public returns (bytes32 requestID) {
        require(whitelistUsers[msg.sender] != Status.Init, "User is not in whitelist");
        require(whitelistUsers[msg.sender] != Status.Pickup, "User already created agent");
        requestID =
            createAgent(msg.sender, projectId, base64Proposal, privateWorkerAddress, serverURL, tokenId, address(0));
        whitelistUsers[msg.sender] = Status.Pickup;
    }
    function createAgentWithWhitelistUsersWithSig(
        bytes32 projectId,
        string memory base64Proposal,
        address privateWorkerAddress,
        string memory serverURL,
        uint256 tokenId,
        bytes memory signature
    ) public returns (bytes32 requestID) {
        bytes32 digest = getRequestDeploymentDigest(projectId, base64Proposal, serverURL);
        address signerAddr = getSignerAddress(digest, signature);
        require(whitelistUsers[signerAddr] != Status.Init, "User is not in whitelist");
        require(whitelistUsers[signerAddr] != Status.Pickup, "User already created agent");
        requestID =
            createAgent(signerAddr, projectId, base64Proposal, privateWorkerAddress, serverURL, tokenId, address(0));
        whitelistUsers[signerAddr] = Status.Pickup;
    }
    function createAgentWithSigWithNFT(
        bytes32 projectId,
        string memory base64Proposal,
        address privateWorkerAddress,
        string memory serverURL,
        bytes memory signature,
        uint256 tokenId
    ) public returns (bytes32 requestID) {
        bytes32 digest = getRequestDeploymentDigest(projectId, base64Proposal, serverURL);
        address signerAddr = getSignerAddress(digest, signature);
        requestID =
            createAgent(signerAddr, projectId, base64Proposal, privateWorkerAddress, serverURL, tokenId, address(0));
    }
    function submitProofOfDeployment(bytes32 projectId, bytes32 requestID, string memory proofBase64)
        public
        hasProject(projectId)
    {
        require(requestID.length > 0, "requestID is empty");
        require(requestDeploymentStatus[requestID].status != Status.Init, "requestID does not exist");
        require(requestDeploymentStatus[requestID].deployWorkerAddr == msg.sender, "Wrong worker address");
        require(requestDeploymentStatus[requestID].status != Status.GeneratedProof, "Already submitted proof");
        requestDeploymentStatus[requestID].status = Status.GeneratedProof;
        deploymentProof[requestID] = proofBase64;
        emit GeneratedProofOfDeployment(projectId, requestID, proofBase64);
    }
    function submitDeploymentRequest(bytes32 projectId, bytes32 requestID)
        public
        hasProject(projectId)
        returns (bool isAccepted)
    {
        require(requestID.length > 0, "requestID is empty");
        require(requestDeploymentStatus[requestID].status != Status.Init, "requestID does not exist");
        require(
            requestDeploymentStatus[requestID].status != Status.Pickup,
            "requestID already picked by another worker, try a different requestID"
        );
        require(
            requestDeploymentStatus[requestID].status != Status.GeneratedProof, "requestID has already submitted proof"
        );
        requestDeploymentStatus[requestID].status = Status.Pickup;
        requestDeploymentStatus[requestID].deployWorkerAddr = msg.sender;
        isAccepted = true;
        emit AcceptDeployment(projectId, requestID, requestDeploymentStatus[requestID].deployWorkerAddr);
    }
    function updateWorkerDeploymentConfigCommon(
        address tokenAddress,
        address userAddress,
        bytes32 projectId,
        bytes32 requestID,
        string memory updatedBase64Config
    ) internal hasProject(projectId) {
        require(requestDeploymentStatus[requestID].status != Status.Init, "requestID does not exist");
        require(bytes(updatedBase64Config).length > 0, "updatedBase64Config is empty");
        require(requestDeploymentStatus[requestID].status != Status.Issued, "requestID is not picked up by any worker");
        require(deploymentOwners[requestID] == userAddress, "Only deployment owner can update config");
        require(paymentAddressEnableMp[tokenAddress], "Invalid token address");
        uint256 cost = paymentOpCostMp[tokenAddress][UPDATE_AGENT_OP];
        if (cost > 0) {
            payWithERC20(tokenAddress, cost, userAddress, feeCollectionWalletAddress);
        }
        if (requestDeploymentStatus[requestID].status == Status.GeneratedProof) {
            requestDeploymentStatus[requestID].status = Status.Pickup;
        }
        emit UpdateDeploymentConfig(
            projectId, requestID, requestDeploymentStatus[requestID].deployWorkerAddr, updatedBase64Config
        );
    }
    function updateWorkerDeploymentConfig(
        address tokenAddress,
        bytes32 projectId,
        bytes32 requestID,
        string memory updatedBase64Config
    ) public {
        updateWorkerDeploymentConfigCommon(tokenAddress, msg.sender, projectId, requestID, updatedBase64Config);
    }
    function updateWorkerDeploymentConfigWithSig(
        address tokenAddress,
        bytes32 projectId,
        bytes32 requestID,
        string memory updatedBase64Config,
        bytes memory signature
    ) public {
        bytes32 digest = getRequestDeploymentDigest(projectId, updatedBase64Config, "app.crestal.network");
        address signerAddr = getSignerAddress(digest, signature);
        updateWorkerDeploymentConfigCommon(tokenAddress, signerAddr, projectId, requestID, updatedBase64Config);
    }
    function setWorkerPublicKey(bytes calldata publicKey) public {
        if (workersPublicKey[msg.sender].length == 0) {
            workerAddressesMp[WORKER_ADDRESS_KEY].push(msg.sender);
        }
        workersPublicKey[msg.sender] = publicKey;
    }
    function getWorkerPublicKey(address workerAddress) external view returns (bytes memory publicKey) {
        publicKey = workersPublicKey[workerAddress];
    }
    function getWorkerAddresses() public view returns (address[] memory) {
        return workerAddressesMp[WORKER_ADDRESS_KEY];
    }
    function getPaymentAddresses() public view returns (address[] memory) {
        return paymentAddressesMp[PAYMENT_KEY];
    }
    function getLatestProposalRequestID(address addr) public view returns (bytes32) {
        return latestProposalRequestID[addr];
    }
    function getLatestDeploymentRequestID(address addr) public view returns (bytes32) {
        return latestDeploymentRequestID[addr];
    }
    function getLatestUserProjectID(address addr) public view returns (bytes32) {
        return latestProjectID[addr];
    }
    function getProjectInfo(bytes32 projectId)
        public
        view
        hasProjectNew(projectId)
        returns (address, bytes32, bytes32[] memory)
    {
        bytes32[] memory requestDeploymentIDs = deploymentIdList[projects[projectId].requestDeploymentID];
        return (projects[projectId].proposedSolverAddr, projects[projectId].requestProposalID, requestDeploymentIDs);
    }
    function getDeploymentProof(bytes32 requestID) public view returns (string memory) {
        return deploymentProof[requestID];
    }
    function getEIP712ContractAddress() public view returns (address) {
        return getAddress();
    }
    function isWhitelistUser(address userAddress) public view returns (bool) {
        return whitelistUsers[userAddress] == Status.Issued || whitelistUsers[userAddress] == Status.Pickup;
    }
    function userTopUp(address tokenAddress, uint256 amount) public {
        require(amount > 0, "Amount must be greater than 0");
        require(paymentAddressEnableMp[tokenAddress], "Payment address is not valid");
        payWithERC20(tokenAddress, amount, msg.sender, feeCollectionWalletAddress);
        userTopUpMp[msg.sender][tokenAddress] += amount;
        emit UserTopUp(msg.sender, feeCollectionWalletAddress, tokenAddress, amount);
    }
}
