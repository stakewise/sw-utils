import pytest

from sw_utils.graph.subgraph_committee import SubgraphCommitteeVotes


class TestSubgraphCommitteeVotes:
    def test_consensus_no_votes(self):
        votes = SubgraphCommitteeVotes([])
        assert votes.has_consensus() is False
        with pytest.raises(ValueError):
            votes.get_consensus_vote()

    def test_consensus_single_vote(self):
        vote_1 = []

        votes = SubgraphCommitteeVotes([None])
        assert votes.has_consensus() is False
        with pytest.raises(ValueError):
            consensus_vote = votes.get_consensus_vote()

        votes = SubgraphCommitteeVotes([vote_1])
        assert votes.has_consensus() is True
        consensus_vote = votes.get_consensus_vote()
        assert consensus_vote == vote_1

    def test_consensus_2_votes(self):
        vote_1 = []
        vote_2 = [{}]

        votes = SubgraphCommitteeVotes([None, vote_1])
        assert votes.has_consensus() is False
        with pytest.raises(ValueError):
            consensus_vote = votes.get_consensus_vote()

        votes = SubgraphCommitteeVotes([vote_1, None])
        assert votes.has_consensus() is False
        with pytest.raises(ValueError):
            consensus_vote = votes.get_consensus_vote()

        votes = SubgraphCommitteeVotes([vote_1, vote_1])
        assert votes.has_consensus() is True
        consensus_vote = votes.get_consensus_vote()
        assert consensus_vote == vote_1

        votes = SubgraphCommitteeVotes([vote_1, vote_2])
        assert votes.has_consensus() is False
        with pytest.raises(ValueError):
            consensus_vote = votes.get_consensus_vote()

        votes = SubgraphCommitteeVotes([vote_2, vote_2])
        assert votes.has_consensus() is True
        consensus_vote = votes.get_consensus_vote()
        assert consensus_vote == vote_2

    def test_consensus_3_votes(self):
        vote_1 = []
        vote_2 = [{}]

        votes = SubgraphCommitteeVotes([vote_1, vote_1, vote_2])
        assert votes.has_consensus() is False
        with pytest.raises(ValueError):
            consensus_vote = votes.get_consensus_vote()

        votes = SubgraphCommitteeVotes([vote_1, vote_1, None])
        assert votes.has_consensus() is False
        with pytest.raises(ValueError):
            consensus_vote = votes.get_consensus_vote()

        votes = SubgraphCommitteeVotes([vote_1, vote_1, vote_1])
        assert votes.has_consensus() is True
        consensus_vote = votes.get_consensus_vote()
        assert consensus_vote == vote_1
