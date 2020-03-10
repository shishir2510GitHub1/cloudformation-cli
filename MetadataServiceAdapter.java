package com.amazonaws.guru.eventhandler.dependency.metadataservice;

import com.amazon.coral.metrics.Metrics;
import com.amazon.guru.connectiontoken.AWSCredentialsBasedConnectionToken;
import com.amazon.guru.connectiontoken.ConnectionToken;
import com.amazon.guru.connectiontoken.OAuthConnectionToken;
import com.amazon.guru.encryption.GuruEncryptionHandler;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.guru.eventhandler.dependency.sts.SecurityTokenServiceAdapter;
import com.amazonaws.guru.eventhandler.domain.DeveloperComment;
import com.amazonaws.guru.eventhandler.domain.GuruRecommendationMetadata;
import com.amazonaws.guru.eventhandler.domain.PullRequest;
import com.amazonaws.guru.eventhandler.domain.PullRequestNotification;
import com.amazonaws.guru.eventhandler.domain.PullRequestSource;
import com.amazonaws.guru.eventhandler.domain.Repository;
import com.amazonaws.guru.eventhandler.exception.DependencyFailureException;
import com.amazonaws.guru.eventhandler.exception.InternalEventHandlerError;
import com.amazonaws.guru.eventhandler.exception.InvalidPullRequestStateException;
import com.amazonaws.guru.eventhandler.exception.UnsupportedThirdPartyException;
import com.amazonaws.guru.eventhandler.exception.nonretryable.InvalidInputException;
import com.amazonaws.guru.eventhandler.exception.retryable.DependencyThrottlingException;
import com.amazonaws.guru.eventhandler.metrics.EventHandlerMetricsHelper;
import com.amazonaws.services.gurumetadataservice.AWSGuruMetadataService;
import com.amazonaws.services.gurumetadataservice.model.AWSGuruMetadataServiceException;
import com.amazonaws.services.gurumetadataservice.model.BadRequestException;
import com.amazonaws.services.gurumetadataservice.model.BatchWriteFeedbackRequest;
import com.amazonaws.services.gurumetadataservice.model.BatchWriteFeedbackResult;
import com.amazonaws.services.gurumetadataservice.model.CodeCommitRepository;
import com.amazonaws.services.gurumetadataservice.model.CodeCommitRepositoryInternal;
import com.amazonaws.services.gurumetadataservice.model.CommitDiffSourceCodeType;
import com.amazonaws.services.gurumetadataservice.model.ConflictException;
import com.amazonaws.services.gurumetadataservice.model.CreateRecommendationJobRequest;
import com.amazonaws.services.gurumetadataservice.model.CreateRecommendationJobResult;
import com.amazonaws.services.gurumetadataservice.model.CredentialsType;
import com.amazonaws.services.gurumetadataservice.model.DescribeRepositoryAssociationInternalRequest;
import com.amazonaws.services.gurumetadataservice.model.DescribeRepositoryAssociationInternalResult;
import com.amazonaws.services.gurumetadataservice.model.Feedback;
import com.amazonaws.services.gurumetadataservice.model.GetConnectionTokenRequest;
import com.amazonaws.services.gurumetadataservice.model.GitHubRepository;
import com.amazonaws.services.gurumetadataservice.model.GitHubRepositoryInternal;
import com.amazonaws.services.gurumetadataservice.model.InternalRecommendationJobState;
import com.amazonaws.services.gurumetadataservice.model.InternalServerErrorException;
import com.amazonaws.services.gurumetadataservice.model.InternalState;
import com.amazonaws.services.gurumetadataservice.model.ListRecommendationJobsRequest;
import com.amazonaws.services.gurumetadataservice.model.ListRecommendationJobsResult;
import com.amazonaws.services.gurumetadataservice.model.ListRecommendationMetadataRequest;
import com.amazonaws.services.gurumetadataservice.model.ListRecommendationMetadataResult;
import com.amazonaws.services.gurumetadataservice.model.PullRequestRecommendationJob;
import com.amazonaws.services.gurumetadataservice.model.PutFeedbackRequest;
import com.amazonaws.services.gurumetadataservice.model.RecommendationJob;
import com.amazonaws.services.gurumetadataservice.model.RecommendationJobDetails;
import com.amazonaws.services.gurumetadataservice.model.RecommendationJobType;
import com.amazonaws.services.gurumetadataservice.model.RecommendationMetadata;
import com.amazonaws.services.gurumetadataservice.model.RepositoryAssociation;
import com.amazonaws.services.gurumetadataservice.model.ResourceNotFoundException;
import com.amazonaws.services.gurumetadataservice.model.SourceCodeType;
import com.amazonaws.services.gurumetadataservice.model.ThrottlingException;
import com.google.common.base.Stopwatch;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static com.amazonaws.guru.eventhandler.metrics.EventHandlerMetrics.RepositoryNotFound;

/**
 * Metadata Service API interactions.
 */
@AllArgsConstructor
@Log4j2
public class MetadataServiceAdapter {

    private static final int MAX_MDS_RECOMMENDATION_JOB_NAME_SIZE = 300;
    private static final int MAX_MDS_BATCH_WRITE_SIZE = 25;

    private final AWSGuruMetadataService mdsClient;
    private final GuruEncryptionHandler encryptionHandler;
    private final SecurityTokenServiceAdapter stsAdapter;

    /**
     * Extract the connection token to extract details (like base commit, etc) from the
     * pull request and validate it.
     * <p>
     * 1. For CodeCommit, the SLR is used.
     * <p>
     * 2. For GitHub, following is the flow to extract the OAUTH token in plaintext:
     * <p>
     * +---------------+                            +----------+              +------------------+
     * | Event handler |                            | Metadata |              |  Key Management  |
     * |    Lambda     |                            | Service  |              |   Service (KMS)  |
     * +---------------+                            +----------+              +------------------+
     * |                                           |                           |
     * New PR --->|                                           |                           |
     * |  describeRepositoryAssociationInternal    |                           |
     * |------------------------------------------>|                           |
     * |                                           |                           |
     * |            credentialID (OAUTH)           |                           |
     * |<------------------------------------------|                           |
     * |                                           |                           |
     * |       getConnectionToken(credID)          |                           |
     * |------------------------------------------>|                           |
     * |                                           |                           |
     * |             OAUTH <encrypted>             |                           |
     * |<------------------------------------------|                           |
     * |                                                                       |
     * |               decryptToken(OAUTH)                                     |
     * |---------------------------------------------------------------------->|
     * |                                                                       |
     * |               OAUTH <plaintext>                                       |
     * |<----------------------------------------------------------------------|
     */
    public ConnectionToken getConnectionToken(final PullRequestNotification pullRequestNotification,
                                              final Repository repository,
                                              final Metrics metrics) {

        log.debug("Calling Mds getConnectionToken for {}", pullRequestNotification);
        final PullRequestSource repoProviderType = pullRequestNotification.getPullRequestSource();

        // It should only be called for GitHub and CodeCommit.
        if (PullRequestSource.GITHUB.equals(repoProviderType)) {
            final String encryptedOauthToken = getConnectionTokenFromMds(pullRequestNotification.getAccountId(),
                                                                         repository.getCredentialId(),
                                                                         metrics);
            final OAuthConnectionToken oauthToken =
                    encryptionHandler.decryptOAuthToken(encryptedOauthToken);
            log.debug("Received OAuthConnectionToken for {}", pullRequestNotification);
            return oauthToken;
        } else if (PullRequestSource.CODECOMMIT.equals(repoProviderType)) {
            final STSAssumeRoleSessionCredentialsProvider slrCreds =
                    (STSAssumeRoleSessionCredentialsProvider)
                            stsAdapter.getGuruServiceLinkedRoleBasedCredentials(pullRequestNotification.getAccountId());

            return AWSCredentialsBasedConnectionToken.builder()
                                                     .awsAccountId(pullRequestNotification.getAccountId())
                                                     .accessKey(slrCreds.getCredentials().getAWSAccessKeyId())
                                                     .secretKey(slrCreds.getCredentials().getAWSSecretKey())
                                                     .sessionToken(slrCreds.getCredentials().getSessionToken())
                                                     .build();
        }

        throw new UnsupportedThirdPartyException(
                String.format("RepositoryType %s is not supported", repoProviderType));
    }

    public Optional<Repository> getRepositoryAssociation(final PullRequestNotification pullRequestNotification,
                                                         final Metrics metrics) {
        log.info("Describing repository association for {}", pullRequestNotification);
        final DescribeRepositoryAssociationInternalRequest describeRequest =
                new DescribeRepositoryAssociationInternalRequest()
                        .withAwsAccountId(pullRequestNotification.getAccountId())
                        .withRepository(getMdsRepository(pullRequestNotification));

        Stopwatch stopwatch = Stopwatch.createStarted();
        try {
            final DescribeRepositoryAssociationInternalResult describeResult =
                    mdsClient.describeRepositoryAssociationInternal(describeRequest);
            stopwatch = stopwatch.stop();
            EventHandlerMetricsHelper.addTimeMillis(metrics,
                                                    "mds:DescribeRepositoryAssociationInternal", stopwatch.elapsed(TimeUnit.MILLISECONDS));
            log.debug("Repository association from MDS is {}", describeResult);
            final String credentialsMappingKey = getCredentialMappingKey(pullRequestNotification.getPullRequestSource());
            final RepositoryAssociation repoAssociation = describeResult.getRepositoryAssociation();
            return Optional.of(Repository.builder()
                                         .repoName(repoAssociation.getRepositoryName())
                                         .repoOwner(repoAssociation.getOwner())
                                         .pullRequestSource(getPullRequestSource(repoAssociation.getProviderType()))
                                         .awsAccountId(repoAssociation.getOwner())
                                         .isAssociated(repoAssociation.getInternalState()
                                                                      .equals(InternalState.AssociationSuccessful.toString()))
                                         .credentialId(repoAssociation.getCredentialsMapping().get(credentialsMappingKey))
                                         .build());
        } catch (final ResourceNotFoundException ex) {
            EventHandlerMetricsHelper.addSingleCount(metrics, RepositoryNotFound.name());
            log.warn("Swallowing ResourceNotFoundException from MDS -", ex);
            return Optional.empty();
        }
    }

    private PullRequestSource getPullRequestSource(final String mdsPullRequestSource) {
        switch (mdsPullRequestSource) {
            case "CodeCommit":
                return PullRequestSource.CODECOMMIT;
            case "GitHub":
                return PullRequestSource.GITHUB;
        }

        throw new InvalidPullRequestStateException(String.format("Source %s isn't supported.", mdsPullRequestSource));
    }

    private String getConnectionTokenFromMds(final String awsAccountId,
                                             final String credentialsId,
                                             final Metrics metrics) {
        log.info("Extracting encrypted OAUTH token from MDS");
        return callMetadataService(() -> mdsClient.getConnectionToken(new GetConnectionTokenRequest()
                                                                              .withAwsAccountId(awsAccountId)
                                                                              .withCredentialsId(credentialsId)),
                                   "mds:GetConnectionToken", awsAccountId, credentialsId,
                                   metrics)
                .getEncryptedCredentials();
    }

    public void createRecommendationJob(final PullRequest pullRequest, final Metrics metrics) {
        log.info("Storing recommendation job for pull request: {}", pullRequest);
        final CreateRecommendationJobRequest createRequest = new CreateRecommendationJobRequest()
                .withAwsAccountId(pullRequest.getAwsAccountId())
                .withRecommendationJobName(getRecommendationJobName(pullRequest))
                .withSourceCode(getSourceCodeType(pullRequest))
                .withClientRequestToken(UUID.randomUUID().toString())
                .withJobType(new RecommendationJobDetails()
                                     .withPullRequest(
                                             new PullRequestRecommendationJob()
                                                     .withPullRequestId(pullRequest.getPullRequestNumber())));

        callMetadataService(() -> callMdsForCreateRecommendationJob(createRequest, pullRequest, metrics),
                            "mds:CreateRecommendationJob",
                            pullRequest.getAwsAccountId(),
                            createRequest.getRecommendationJobName(),
                            metrics);
    }

    private CreateRecommendationJobResult callMdsForCreateRecommendationJob(final CreateRecommendationJobRequest createRequest,
                                                                            final PullRequest pullRequest,
                                                                            final Metrics metrics) {
        try {
            log.debug("Trying to create recommendation job {}", createRequest);
            final CreateRecommendationJobResult createResult = mdsClient.createRecommendationJob(createRequest);
            log.debug("Output of MDS create recommendation job API: {}", createResult);
            return createResult;
        } catch (final ConflictException ex) {
            // Conflict Exception denotes that the job already exist, hence swallowing
            EventHandlerMetricsHelper.addSingleCount(metrics, "PullRequestRecommendationJobExist");
            log.debug("Recommendation job for pull request {} already exists", pullRequest);
            // it doesn't matter what we return from here since the output is not used.
            return null;
        }
    }

    public String getRecommendationJobName(final PullRequest pullRequest) {
        final String jobName = String.join("-",
                                           pullRequest.getPullRequestSource().name(),
                                           pullRequest.getHead().getRepoName(),
                                           pullRequest.getPullRequestNumber(),
                                           pullRequest.getHead().getCommitSha());

        return jobName.length() > MAX_MDS_RECOMMENDATION_JOB_NAME_SIZE ?
               jobName.substring(0, MAX_MDS_RECOMMENDATION_JOB_NAME_SIZE) : jobName;
    }

    private SourceCodeType getSourceCodeType(final PullRequest pullRequest) {

        final PullRequestSource pullRequestSource = pullRequest.getPullRequestSource();
        final com.amazonaws.services.gurumetadataservice.model.Repository sourceRepository;
        final com.amazonaws.services.gurumetadataservice.model.Repository destinationRepository;

        switch (pullRequestSource) {
            case CODECOMMIT:
                sourceRepository = new com.amazonaws.services.gurumetadataservice.model.Repository()
                        .withCodeCommit(new CodeCommitRepository().withName(pullRequest.getHead().getRepoName()));
                destinationRepository = new com.amazonaws.services.gurumetadataservice.model.Repository()
                        .withCodeCommit(new CodeCommitRepository().withName(pullRequest.getDiff().getRepoName()));
                break;
            case GITHUB:
                sourceRepository = new com.amazonaws.services.gurumetadataservice.model.Repository()
                        .withGitHub(new GitHubRepository()
                                            .withName(pullRequest.getHead().getRepoName())
                                            .withOwner(pullRequest.getHead().getOwner())
                                            .withCredentialsId(pullRequest.getHead().getCredentialId()));
                destinationRepository = new com.amazonaws.services.gurumetadataservice.model.Repository()
                        .withGitHub(new GitHubRepository()
                                            .withName(pullRequest.getDiff().getRepoName())
                                            .withOwner(pullRequest.getDiff().getOwner())
                                            .withCredentialsId(pullRequest.getDiff().getCredentialId()));
                break;
            case BITBUCKET:
            default:
                throw new IllegalArgumentException("Unsupported pull request source " + pullRequestSource);
        }
        return new SourceCodeType().withCommitDiff(new CommitDiffSourceCodeType()
                                                           .withSourceCommit(pullRequest.getHead().getCommitSha())
                                                           .withDestinationCommit(pullRequest.getDiff().getCommitSha())
                                                           .withSourceRepository(sourceRepository)
                                                           .withDestinationRepository(destinationRepository));
    }

    public List<GuruRecommendationMetadata> listRecommendationsMetadata(final PullRequest pullRequest,
                                                                        final Metrics metrics) {
        String nextToken;
        final List<RecommendationMetadata> recommendations = new ArrayList<>();
        final ListRecommendationMetadataRequest listRecommendationMetadataRequest =
                new ListRecommendationMetadataRequest().withRecommendationJobName(getRecommendationJobName(pullRequest))
                                                       .withAwsAccountId(pullRequest.getAwsAccountId())
                                                       .withRecommendationJobType(RecommendationJobType.PullRequest);
        do {
            final ListRecommendationMetadataResult callResult =
                    callMetadataService(() -> mdsClient.listRecommendationMetadata(listRecommendationMetadataRequest),
                                        "mds:ListRecommendationMetadata",
                                        pullRequest.getAwsAccountId(),
                                        listRecommendationMetadataRequest.getRecommendationJobName(),
                                        metrics);
            listRecommendationMetadataRequest.setNextToken(callResult.getNextToken());
            recommendations.addAll(callResult.getRecommendationMetadata());
            nextToken = callResult.getNextToken();
        } while (null != nextToken);

        return recommendations.stream()
                              .map(recommendation ->
                                           GuruRecommendationMetadata.builder()
                                                                     .publishedRecommendationId(
                                                                             recommendation.getProviderCommentId())
                                                                     .recommendationId(recommendation.getRecommendationId())
                                                                     .build())
                              .collect(Collectors.toList());
    }

    public List<DeveloperComment> batchWriteFeebacks(final List<DeveloperComment> capturedFeedback,
                                                     final PullRequest pullRequest,
                                                     final Metrics metrics) {


        final List<Feedback> mdsFeedbacks =
                capturedFeedback.stream()
                                .map(feedback -> new Feedback()
                                        .withAwsAccountId(pullRequest.getAwsAccountId())
                                        .withRecommendationJobId(getRecommendationJobName(pullRequest))

                                        // Here we're sure that inReplyTo will be present
                                        // Otherwise we'd want to fail
                                        .withReplyTo(feedback.inReplyTo()
                                                             .orElseThrow(() -> new IllegalStateException("InReplyTo should be set")))

                                        .withUser(feedback.getUserInfo())
                                        .withCreatedAt(feedback.getCreationDate())
                                        .withReactions(feedback.getReactionsMap())
                                        .withMessage(feedback.getContent())

                                        // here we're storing commentId as recommendationId since
                                        // Feedback Table Range key is recommendationId which
                                        // should be unique for different feedback on a singe guru recommendation
                                        // TODO: Add a new field for GuruRecommendationId
                                        .withRecommendationId(feedback.getCommentId()))
                                .collect(Collectors.toList());

        // MDS batchWrite API takes only input size of 25 max
        // Dividing list into 25 items
        final Collection<List<Feedback>> batchFeedbackList = partitionList(mdsFeedbacks);
        final List<Feedback> unprocessedFeedbacks = new ArrayList<>();
        for (final List<Feedback> batchedFeedbacks : batchFeedbackList) {
            log.debug("Trying to store {} feedbacks : {}", batchedFeedbacks.size(), batchedFeedbacks);
            final BatchWriteFeedbackResult result =
                    callMetadataService(
                            () -> mdsClient.batchWriteFeedback(new BatchWriteFeedbackRequest().withFeedbackItems(batchedFeedbacks)),
                            "mds:BatchWriteFeedback",
                            pullRequest.getAwsAccountId(),
                            getRecommendationJobName(pullRequest),
                            metrics);
            unprocessedFeedbacks.addAll(result.getUnprocessedFeedback());
        }

        final List<DeveloperComment> unprocessedDeveloperComments = getUnprocessedDeveloperFeedback(unprocessedFeedbacks);

        if (!unprocessedFeedbacks.isEmpty()) {
            log.error("Unable to store feedbacks {} ", unprocessedDeveloperComments);
        }
        return unprocessedDeveloperComments;
    }

    private List<DeveloperComment> getUnprocessedDeveloperFeedback(final List<Feedback> unprocessedFeedbacks) {
        return unprocessedFeedbacks.stream()
                                   .map(unprocessedFeedback ->
                                                DeveloperComment.builder()
                                                                .commentId(unprocessedFeedback.getRecommendationId())
                                                                .inReplyTo(unprocessedFeedback.getReplyTo())
                                                                .lastModifiedInstant(unprocessedFeedback.getCreatedAt()
                                                                                                        .toInstant())
                                                                .userInfo(unprocessedFeedback.getUser())
                                                                .build())
                                   .collect(Collectors.toList());
    }

    public void putFeedback(final Feedback feedback, final Metrics metrics) {
        final PutFeedbackRequest request = new PutFeedbackRequest();
        request.setItem(feedback);
        callMetadataService(() -> mdsClient.putFeedback(request),
                            "mds:PutFeedback",
                            feedback.getAwsAccountId(),
                            feedback.getRecommendationJobId(),
                            metrics);
    }

    private <T> Collection<List<T>> partitionList(
            final List<T> capturedFeedbacks) {
        final AtomicInteger counter = new AtomicInteger();
        return capturedFeedbacks.stream()
                                .collect(Collectors.groupingBy(i -> counter.getAndIncrement() / MAX_MDS_BATCH_WRITE_SIZE))
                                .values();
    }

    private com.amazonaws.services.gurumetadataservice.model.RepositoryInternal getMdsRepository(
            final PullRequestNotification pullRequestNotification) {
        log.debug("Returning MDS repository for notification: {}", pullRequestNotification);
        final com.amazonaws.services.gurumetadataservice.model.RepositoryInternal mdsRepository =
                new com.amazonaws.services.gurumetadataservice.model.RepositoryInternal();

        if (pullRequestNotification.getPullRequestSource().equals(PullRequestSource.GITHUB)) {
            mdsRepository.setGitHub(new GitHubRepositoryInternal()
                                            .withName(pullRequestNotification.getRepoName())
                                            .withOwner(pullRequestNotification.getRepoOwner()));
        } else if (pullRequestNotification.getPullRequestSource().equals(PullRequestSource.CODECOMMIT)) {
            mdsRepository.setCodeCommit(new CodeCommitRepositoryInternal()
                                                .withName(pullRequestNotification.getRepoName()));
        } else {
            log.error("Unsupported pull request source for repository: {}", pullRequestNotification);
            throw new InvalidPullRequestStateException(String.format("Unsupported pull request source: %s",
                                                                     pullRequestNotification.getPullRequestSource()));
        }

        return mdsRepository;
    }

    private String getCredentialMappingKey(final PullRequestSource pullRequestSource) {
        switch (pullRequestSource) {
            case CODECOMMIT:
                return CredentialsType.FAS.toString();
            case GITHUB:
                return CredentialsType.OAUTH.toString();
            case BITBUCKET:
            default:
                throw new IllegalArgumentException("Unsupported pull request source " + pullRequestSource);
        }
    }

    public List<com.amazonaws.guru.eventhandler.domain.RecommendationJob> listRecommendationsForPullRequest(
            final PullRequestNotification pullRequest,
            final Metrics metrics) {
        final List<com.amazonaws.guru.eventhandler.domain.RecommendationJob> recommendationJobs = new ArrayList<>();
        final ListRecommendationJobsRequest req =
                new ListRecommendationJobsRequest().withAwsAccountId(pullRequest.getAccountId())
                                                   .withJobTypes(RecommendationJobType.PullRequest)
                                                   .withNames(pullRequest.getRepoName())
                                                   .withOwners(pullRequest.getRepoOwner())
                                                   .withProviderTypes(getProviderTypeFromPullRequestSource(
                                                           pullRequest.getPullRequestSource()))
                                                   .withPullRequestIds(pullRequest.getPullRequestNumber());

        String nextToken;
        do {
            final ListRecommendationJobsResult callResult =
                    callMetadataService(() -> mdsClient.listRecommendationJobs(req),
                                        "mds:ListRecommendationJobs",
                                        pullRequest.getAccountId(),
                                        String.format("%s/%s/%s",
                                                      pullRequest.getRepoOwner(),
                                                      pullRequest.getRepoName(),
                                                      pullRequest.getPullRequestNumber()),
                                        metrics);
            recommendationJobs.addAll(callResult.getRecommendationJobs()
                                                .stream()
                                                // filtering out recommendation jobs which are in failed non-retryable
                                                // state as commitIds of those jobs have not been successfully analyzed
                                                .filter(r -> {
                                                    if (r.getInternalState().equals(
                                                            InternalRecommendationJobState.FailedNonRetryable.toString())) {
                                                        log.debug("Filtering out {} as it is in FailedNonRetryable state", r);
                                                        return false;
                                                    }
                                                    return true;
                                                })
                                                .map(r -> mapToEventHandlerJob(r, pullRequest.getAccountId()))
                                                .collect(Collectors.toList()));
            nextToken = callResult.getNextToken();
            req.setNextToken(nextToken);
        } while (null != nextToken);

        log.debug("Found {} recommendation jobs: {}", recommendationJobs.size(), recommendationJobs);
        return recommendationJobs;
    }

    private com.amazonaws.guru.eventhandler.domain.RecommendationJob mapToEventHandlerJob(final RecommendationJob mdsJob,
                                                                                          final String awsAccountId) {
        final CommitDiffSourceCodeType commitDiff = mdsJob.getSourceCode().getCommitDiff();
        if (commitDiff == null) {
            throw new IllegalStateException(String.format("CommitDiff not present for %s", mdsJob));
        }
        final com.amazonaws.guru.eventhandler.domain.RecommendationJob.CommitMetadata sourceCommit =
                com.amazonaws.guru.eventhandler.domain.RecommendationJob.CommitMetadata
                        .builder()
                        .commitSha(commitDiff.getSourceCommit())
                        .repoName(getRepoName(commitDiff.getSourceRepository()))
                        .repoOwner(getRepoOwner(commitDiff.getDestinationRepository(), awsAccountId))
                        .build();
        final com.amazonaws.guru.eventhandler.domain.RecommendationJob.CommitMetadata destCommit =
                com.amazonaws.guru.eventhandler.domain.RecommendationJob.CommitMetadata
                        .builder()
                        .commitSha(commitDiff.getDestinationCommit())
                        .repoName(getRepoName(commitDiff.getDestinationRepository()))
                        .repoOwner(getRepoOwner(commitDiff.getDestinationRepository(), awsAccountId))
                        .build();
        return com.amazonaws.guru.eventhandler.domain.RecommendationJob.builder()
                                                                       .source(sourceCommit)
                                                                       .destination(destCommit)
                                                                       .pullRequestNumber(mdsJob.getPullRequestId())
                                                                       .creationTime(mdsJob.getCreatedTimeStamp().toInstant())
                                                                       .build();

    }

    private String getRepoName(final com.amazonaws.services.gurumetadataservice.model.Repository repository) {
        if (repository.getCodeCommit() != null) {
            return repository.getCodeCommit().getName();
        }
        return repository.getGitHub().getName();
    }

    private String getRepoOwner(final com.amazonaws.services.gurumetadataservice.model.Repository repository,
                                final String awsAccountId) {
        if (repository.getGitHub() != null) {
            return repository.getGitHub().getOwner();
        }
        // for CodeCommit, owner is the account root
        return awsAccountId;
    }

    private String getProviderTypeFromPullRequestSource(final PullRequestSource source) {
        switch (source) {
            case GITHUB:
                return "GitHub";
            case CODECOMMIT:
                return "CodeCommit";
            case BITBUCKET:
            default:
                throw new IllegalStateException(String.format("Unknown PullRequestSource: %s", source));
        }
    }

    private <T> T callMetadataService(final Supplier<T> call,
                                      final String apiName,
                                      final String awsAccountId,
                                      final String resourceName,
                                      final Metrics metrics) {
        final long startTime = System.currentTimeMillis();
        try {
            final T result = call.get();
            EventHandlerMetricsHelper.addTimeMillis(metrics, apiName, System.currentTimeMillis() - startTime);
            return result;
        } catch (final AWSGuruMetadataServiceException ex) {
            EventHandlerMetricsHelper.addTimeMillis(metrics, apiName, System.currentTimeMillis() - startTime);
            throw handleMetadataServiceException(ex, apiName, awsAccountId, resourceName, metrics);
        }
    }


    private RuntimeException handleMetadataServiceException(final AWSGuruMetadataServiceException exception,
                                                            final String apiName,
                                                            final String awsAccountId,
                                                            final String resourceName,
                                                            final Metrics metrics) {
        EventHandlerMetricsHelper.addExceptionMetric(metrics, apiName, exception);
        if (exception instanceof ResourceNotFoundException) {
            throw new InvalidInputException(String.format("%s is not found for %s when calling %s",
                                                          resourceName, awsAccountId, apiName),
                                            exception);
        } else if (exception instanceof BadRequestException) {
            throw new InvalidInputException(String.format("%s is not valid for %s when calling %s",
                                                          resourceName, awsAccountId, apiName),
                                            exception);
        } else if (exception instanceof ThrottlingException) {
            throw new DependencyThrottlingException(String.format("Throttled by MDS when calling %s for account %s for %s",
                                                                  apiName, awsAccountId, resourceName),
                                                    exception);
        } else if (exception instanceof InternalServerErrorException ||
                Response.Status.Family.SERVER_ERROR.equals(Response.Status.Family.familyOf(exception.getStatusCode()))) {
            throw new DependencyFailureException("MDS failed ", exception);
        }

        throw new InternalEventHandlerError(String.format("Unknown exception from MDS for account %s when calling %s for resource %s",
                                                          awsAccountId, apiName, resourceName),
                                            exception);
    }
}
