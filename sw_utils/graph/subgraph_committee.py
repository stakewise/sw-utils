import asyncio
import logging
from typing import TypeAlias, cast

from eth_typing import BlockNumber
from graphql import DocumentNode

from sw_utils.graph.client import GraphClient

logger = logging.getLogger(__name__)


SubgraphVote: TypeAlias = list[dict]


class SubgraphCommittee:
    def __init__(
        self, endpoints: list[str], request_timeout: int, retry_timeout: int, page_size: int = 100
    ) -> None:
        self.graph_clients = []
        self.page_size = page_size

        for endpoint in endpoints:
            graph_client = GraphClient(
                endpoint=endpoint,
                request_timeout=request_timeout,
                retry_timeout=retry_timeout,
            )
            self.graph_clients.append(graph_client)

    async def fetch_votes(
        self, query: DocumentNode, block_number: BlockNumber
    ) -> 'SubgraphCommitteeVotes':
        subgraph_votes = await asyncio.gather(
            *[
                self._fetch_vote(
                    graph_client=graph_client,
                    query=query,
                    block_number=block_number,
                )
                for graph_client in self.graph_clients
            ]
        )
        return SubgraphCommitteeVotes(subgraph_votes)

    async def _fetch_vote(
        self,
        graph_client: GraphClient,
        query: DocumentNode,
        block_number: BlockNumber,
    ) -> SubgraphVote | None:
        try:
            return await graph_client.fetch_pages(
                query=query,
                page_size=self.page_size,
                params={'blockNumber': block_number},
            )
        except Exception as e:
            logger.warning('Failed to fetch vote from %s: %s', graph_client.endpoint, e)
            return None


class SubgraphCommitteeVotes:
    def __init__(self, subgraph_votes: list[SubgraphVote | None]) -> None:
        self.subgraph_votes = subgraph_votes

    def has_consensus(self) -> bool:
        if not self.subgraph_votes:
            return False

        vote = self.subgraph_votes[0]

        if vote is None:
            return False

        return all(vote == subgraph_vote for subgraph_vote in self.subgraph_votes)

    def get_consensus_vote(self) -> SubgraphVote:
        if not self.has_consensus():
            raise ValueError('No consensus')

        # First vote is not None because consensus is reached
        return cast(SubgraphVote, self.subgraph_votes[0])
