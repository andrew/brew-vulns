# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "brew/vulns"

require "minitest/autorun"
require "webmock/minitest"
