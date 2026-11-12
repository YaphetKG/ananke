"""PullRequestManager.upsert: create vs update, labels, user and team reviewers. Offline."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from fakes import finding, item_for

from ananke.config import GitHubConfig
from ananke.github.auth import GitHubAuth
from ananke.github.client import GitHubClient
from ananke.github.prs import PullRequestManager, split_reviewers

API = "https://api.github.com"
REPO = "RENCI/example-repo"


def test_split_reviewers():
    assert split_reviewers(["alice", "@bob", "RENCI/platform-team"]) == (
        ["alice", "bob"],
        ["platform-team"],
    )


@pytest.fixture
async def prs():
    auth = GitHubAuth.from_config(GitHubConfig(token="ghp_test"))
    async with httpx.AsyncClient() as http:
        yield PullRequestManager(GitHubClient(auth, api_url=API, client=http))


@respx.mock
async def test_upsert_creates_pr_labels_and_reviewers(prs):
    item = item_for(finding())
    respx.get(f"{API}/repos/{REPO}/pulls").respond(json=[])
    create = respx.post(f"{API}/repos/{REPO}/pulls").respond(
        201, json={"number": 9, "html_url": "https://github.com/x/pull/9"}
    )
    respx.get(f"{API}/repos/{REPO}/labels/ananke").respond(200, json={"name": "ananke"})
    respx.get(f"{API}/repos/{REPO}/labels/security").respond(404, json={"message": "Not Found"})
    new_label = respx.post(f"{API}/repos/{REPO}/labels").respond(201, json={})
    add_labels = respx.post(f"{API}/repos/{REPO}/issues/9/labels").respond(200, json=[])
    reviewers = respx.post(f"{API}/repos/{REPO}/pulls/9/requested_reviewers").respond(201, json={})

    pr = await prs.upsert(item, base="main", title="t", body="b", reviewers=["alice", "RENCI/sec"])

    assert (pr.number, pr.url) == (9, "https://github.com/x/pull/9")
    assert json.loads(create.calls.last.request.content) == {
        "title": "t", "head": item.branch, "base": "main", "body": "b"
    }  # fmt: skip
    assert json.loads(new_label.calls.last.request.content)["name"] == "security"
    assert json.loads(add_labels.calls.last.request.content) == {"labels": ["ananke", "security"]}
    assert json.loads(reviewers.calls.last.request.content) == {
        "reviewers": ["alice"], "team_reviewers": ["sec"]
    }  # fmt: skip


@respx.mock
async def test_upsert_updates_existing_pr(prs):
    item = item_for(finding())
    respx.get(f"{API}/repos/{REPO}/pulls").respond(
        json=[{"number": 4, "head": {"ref": item.branch}}]
    )
    patch = respx.patch(f"{API}/repos/{REPO}/pulls/4").respond(200, json={"number": 4})
    create = respx.post(f"{API}/repos/{REPO}/pulls")
    respx.get(url__regex=rf"{API}/repos/{REPO}/labels/.*").respond(200, json={})
    respx.post(f"{API}/repos/{REPO}/issues/4/labels").respond(200, json=[])

    pr = await prs.upsert(item, base="main", title="t2", body="b2")
    assert pr.number == 4 and not create.called
    assert json.loads(patch.calls.last.request.content) == {"title": "t2", "body": "b2"}
