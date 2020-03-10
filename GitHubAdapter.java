package com.amazonaws.guru.eventhandler.dependency.thirdparty.github;

import com.amazon.coral.metrics.Metrics;
import com.amazonaws.guru.common.exceptions.GitHubApiException;
import com.amazonaws.guru.common.github.GitHubApiFacade;
import com.amazonaws.guru.common.github.GitHubApiFacadeFactory;
import com.amazonaws.guru.common.github.GitHubPaginatedResult;
import com.amazonaws.guru.common.github.domain.GitHubCommentResponse;
import com.amazonaws.guru.common.github.domain.GitHubPullRequest;
import com.amazonaws.guru.common.github.domain.GitHubPullRequestCommit;
import com.amazonaws.guru.eventhandler.dependency.metadataservice.MetadataServiceAdapter;
import com.amazonaws.guru.eventhandler.dependency.thirdparty.ThirdPartyAdapter;
import com.amazonaws.guru.eventhandler.domain.DeveloperComment;
import com.amazonaws.guru.eventhandler.domain.EventHandlerConstants;
import com.amazonaws.guru.eventhandler.domain.PullRequest;
import com.amazonaws.guru.eventhandler.domain.PullRequest.CommitReference;
import com.amazonaws.guru.eventhandler.domain.PullRequestNotification;
import com.amazonaws.guru.eventhandler.domain.PullRequestSource;
import com.amazonaws.guru.eventhandler.domain.RecommendationJob;
import com.amazonaws.guru.eventhandler.domain.Repository;
import com.amazonaws.guru.eventhandler.exception.ExceptionHandler;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableMap;
import lombok.NonNull;
import lombok.extern.log4j.Log4j2;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;


@Log4j2
public class GitHubAdapter implements ThirdPartyAdapter {

    private final GitHubApiFacadeFactory gitHubClientFactory;
    private final MetadataServiceAdapter mdsAdapter;

    public GitHubAdapter(final GitHubApiFacadeFactory gitHubClientFactory, final MetadataServiceAdapter mdsAdapter) {
        this.gitHubClientFactory = gitHubClientFactory;
        this.mdsAdapter = mdsAdapter;
    }

    /**
     * Get PullRequest metadata from GitHub.
     *
     * @param repo                GitHub Repository.
     * @param oauthToken          which grants access to GitHub repository.
     * @param webhookNotification received from WebhookService.
     * @return PullRequest POJO
     */
    // TODO: Add exception handling for GitHub 4xx vs 5xx
    @Override
    public PullRequest verifyAndGetPullRequest(@NonNull final PullRequestNotification webhookNotification,
                                               @NonNull final Repository repo,
                                               @NonNull final String oauthToken,
                                               final Metrics metrics) {

        try {
            final GitHubApiFacade gitHubApiFacade = gitHubClientFactory.createApiFacade(oauthToken, metrics);

            final GitHubPullRequest gitHubPullRequest =
                    gitHubApiFacade.getPullRequest(webhookNotification.getRepoOwner(),
                                                   webhookNotification.getRepoName(),
                                                   Integer.parseInt(webhookNotification.getPullRequestNumber()));

            final GitHubPullRequestCommit diffCommit = getPullRequestDiffCommit(gitHubPullRequest,
                                                                                webhookNotification,
                                                                                metrics);

            return buildPullRequest(repo, gitHubPullRequest, diffCommit, webhookNotification);
        } catch (final GitHubApiException ex) {
            throw ExceptionHandler.handleGitHubExceptions(ex, "gitHub:GetPullRequest", webhookNotification.getAccountId(),
                                                          String.format("%s/pulls/%s",
                                                                        webhookNotification.getFullRepoName(),
                                                                        webhookNotification.getPullRequestNumber()));
        }
    }

    @Override
    public List<DeveloperComment> getPullRequestComments(@NonNull final PullRequest pullRequest,
                                                         @NonNull final Repository repository,
                                                         @NonNull final String oauthToken,
                                                         final Metrics metrics) {

        final GitHubApiFacade gitHubApiFacade = gitHubClientFactory.createApiFacade(oauthToken);
        final List<GitHubCommentResponse> comments = new ArrayList<>();
        final int pullRequestNumber = Integer.parseInt(pullRequest.getPullRequestNumber());
        String nextToken = null;
        do {
            try {
                final GitHubPaginatedResult<GitHubCommentResponse> commentsOnPullRequest =
                        gitHubApiFacade.getCommentsOnPullRequest(repository.getRepoOwner(),
                                                                 repository.getRepoName(),
                                                                 pullRequestNumber,
                                                                 true,
                                                                 nextToken);
                comments.addAll(commentsOnPullRequest.getResults());
                nextToken = commentsOnPullRequest.getNextToken();
            } catch (final GitHubApiException ex) {
                throw ExceptionHandler.handleGitHubExceptions(ex,
                                                              "github:GetCommentsOnPullRequest",
                                                              String.format("%s/pulls/%s",
                                                                            pullRequest.getPullRequestNotification().getFullRepoName(),
                                                                            pullRequest.getPullRequestNumber()),
                                                              pullRequest.getAwsAccountId());
            }
        } while (nextToken != null);

        return comments.stream().map(comment ->
                                             DeveloperComment.builder()
                                                             .userId(comment.getUser().getLogin())
                                                             .content(comment.getBody())
                                                             .deleted(false)
                                                             .inReplyTo(String.valueOf(comment.getInReplyTo()))
                                                             .commentId(String.valueOf(comment.getCommentId()))
                                                             .reactionsMap(comment.getReactionsMap())
                                                             .userInfo(ImmutableMap.of(EventHandlerConstants.GITHUB_USER_ID,
                                                                                       comment.getUser().getLogin()))
                                                             .lastModifiedInstant(Instant.parse(comment.getUpdatedAt()))
                                                             .build())
                       .collect(Collectors.toList());

    }

    private PullRequest buildPullRequest(@NonNull final Repository repository,
                                         @NonNull final GitHubPullRequest gitHubPullRequest,
                                         @NonNull final GitHubPullRequestCommit gitHubDiffCommit,
                                         final PullRequestNotification webhookNotification) {

        // headCommit
        final GitHubPullRequestCommit gitHubHead = gitHubPullRequest.getHead();
        final CommitReference headCommit = buildCommitReference(gitHubHead.getSha(),
                                                                gitHubHead.getRepo().getName(),
                                                                gitHubHead.getRepo().getOwner().getLogin(),
                                                                repository.getCredentialId());

        // baseCommit
        final GitHubPullRequestCommit gitHubBase = gitHubPullRequest.getBase();
        final CommitReference baseCommit = buildCommitReference(gitHubBase.getSha(),
                                                                gitHubBase.getRepo().getName(),
                                                                gitHubBase.getRepo().getOwner().getLogin(),
                                                                repository.getCredentialId());

        // diffCommit
        final CommitReference diffCommit = buildCommitReference(gitHubDiffCommit.getSha(),
                                                                gitHubDiffCommit.getRepo().getName(),
                                                                gitHubDiffCommit.getRepo().getOwner().getLogin(),
                                                                repository.getCredentialId());

        return PullRequest.builder()
                          .pullRequestSource(PullRequestSource.GITHUB)
                          .awsAccountId(webhookNotification.getAccountId())
                          .createdAt(gitHubPullRequest.getCreatedAt())
                          .updatedAt(gitHubPullRequest.getUpdatedAt())
                          .pullRequestNumber(String.valueOf(gitHubPullRequest.getNumber()))
                          .head(headCommit)
                          .base(baseCommit)
                          .diff(diffCommit)
                          .pullRequestState(gitHubPullRequest.getState())
                          .pullRequestNotification(webhookNotification)
                          .build();
    }

    /**
     * This method returns the intermediate commit until which CodeGuru has analyzed the pull-request. There can
     * be the following cases:
     * <ul>
     *  <li>
     *      New Pull Request: If a new PR is created, then Guru wouldn't have analyzed any commit, and therefore
     *      this method will return the destination/base commit as the diff-commit. <br>
     *  </li>
     *  <li>
     *      Pull Request Update with a single commit: If a PR gets updated with a single commit, intermediate commit
     *      will be equal to the last recommendation job which ran successfully for this PR. This will be found out
     *      by calling MDS ListRecommendationJobs API.
     *  </li>
     *  <li>
     *      Pull Request Update With multiple commits: If a PR gets updated with multiple commit, intermediate commit
     *      will be equal to the same as last case, corresponding to the last successfully ran recommendation job.
     *  </li>
     *  <li>
     *      Pull Request Update with force push: Same as above, force push will create a new commit, and therefore
     *      MDS ListRecommendationJobs will be able to tell us the last processed job.
     *  </li>
     * </ul>
     *
     * @param pullRequest         : PullRequest Object
     * @param webhookNotification : Webhook Notification
     * @param metrics             : metrics object
     * @return: GitHubPullRequestCommit corresponding to last successfully processed recommendation job.
     */
    @VisibleForTesting
    GitHubPullRequestCommit getPullRequestDiffCommit(@NonNull final GitHubPullRequest pullRequest,
                                                     @NonNull final PullRequestNotification webhookNotification,
                                                     final Metrics metrics) {
        final List<RecommendationJob> recommendationJobs =
                mdsAdapter.listRecommendationsForPullRequest(webhookNotification, metrics);

        // if no recommendation jobs have been processed, this must be the first pull request notification
        // return base/destination commit as diff commit
        if (recommendationJobs.isEmpty()) {
            return pullRequest.getBase();
        }

        // sort by timestamp (defined in RecommendationJob class)
        recommendationJobs.sort(RecommendationJob.DATE_BASED_COMPARATOR);
        log.debug("Sorted recommendation jobs {}, selecting first job as last processed {}",
                  recommendationJobs, recommendationJobs.get(0));

        final RecommendationJob lastJob = recommendationJobs.get(0);
        final String lastProcessedCommit = lastJob.getSource().getCommitSha();

        return GitHubPullRequestCommit.builder()
                                      .sha(lastProcessedCommit)
                                      // This is Important: Setting repo as base repo!
                                      // If we do not set repo as base repo, forked use-case will stop working.
                                      // Forked repo can be cloned using base/parent repo
                                      // https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-forks
                                      .repo(pullRequest.getBase().getRepo())
                                      .build();

    }

    private CommitReference buildCommitReference(@NonNull final String commitSha, @NonNull final String repoName,
                                                 @NonNull final String owner,
                                                 @NonNull final String credentialId) {
        return CommitReference.builder()
                              .commitSha(commitSha)
                              .repoName(repoName)
                              .owner(owner)
                              .credentialId(credentialId)
                              .build();
    }

    private <T> T callGitHub(final Supplier<T> call,
                             final String apiName,
                             final String awsAccountId,
                             final String resourceName) {
        try {
            return call.get();
        } catch (final GitHubApiException ex) {
            throw ExceptionHandler.handleGitHubExceptions(ex, apiName, awsAccountId, resourceName);
        }
    }


    @Override
    public PullRequestSource supportedThirdParty() {
        return PullRequestSource.GITHUB;
    }
}
