# frozen_string_literal: true

require "test_helper"

class TestOsvClient < Minitest::Test
  def setup
    @client = Brew::Vulns::OsvClient.new
  end

  def test_query_returns_vulnerabilities
    stub_request(:post, "https://api.osv.dev/v1/query")
      .with(body: {
        package: { name: "https://github.com/openssl/openssl", ecosystem: "GIT" },
        version: "openssl-3.0.0"
      }.to_json)
      .to_return(
        status: 200,
        body: { vulns: [{ id: "CVE-2024-1234", summary: "Test vulnerability" }] }.to_json
      )

    vulns = @client.query(repo_url: "https://github.com/openssl/openssl", version: "openssl-3.0.0")

    assert_equal 1, vulns.size
    assert_equal "CVE-2024-1234", vulns.first["id"]
  end

  def test_query_returns_empty_array_when_no_vulnerabilities
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_return(status: 200, body: {}.to_json)

    vulns = @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")

    assert_equal [], vulns
  end

  def test_query_batch_returns_results_for_each_package
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(
        status: 200,
        body: {
          results: [
            { vulns: [{ id: "CVE-2024-1111" }] },
            { vulns: [] },
            { vulns: [{ id: "CVE-2024-2222" }, { id: "CVE-2024-3333" }] }
          ]
        }.to_json
      )

    packages = [
      { repo_url: "https://github.com/a/a", version: "v1" },
      { repo_url: "https://github.com/b/b", version: "v2" },
      { repo_url: "https://github.com/c/c", version: "v3" }
    ]

    results = @client.query_batch(packages)

    assert_equal 3, results.size
    assert_equal 1, results[0].size
    assert_equal 0, results[1].size
    assert_equal 2, results[2].size
  end

  def test_query_batch_returns_empty_array_for_empty_input
    results = @client.query_batch([])
    assert_equal [], results
  end

  def test_raises_api_error_on_http_error
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_return(status: 500, body: "Internal Server Error")

    assert_raises(Brew::Vulns::OsvClient::ApiError) do
      @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")
    end
  end

  def test_handles_pagination
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_return(
        { status: 200, body: { vulns: [{ id: "CVE-1" }], next_page_token: "token123" }.to_json },
        { status: 200, body: { vulns: [{ id: "CVE-2" }] }.to_json }
      )

    vulns = @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")

    assert_equal 2, vulns.size
    assert_equal "CVE-1", vulns[0]["id"]
    assert_equal "CVE-2", vulns[1]["id"]
  end
end
