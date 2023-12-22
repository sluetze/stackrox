#!/usr/bin/env bats
# shellcheck disable=SC1091

load "../../../scripts/test_helpers.bats"

function setup() {
    source "${BATS_TEST_DIRNAME}/../lib.sh"
}

@test "expects args" {
    run summarize_check_output
    assert_failure
    assert_output --partial 'missing args'
}

@test "takes the first line from the output" {
    check_out="$(cat "${BATS_TEST_DIRNAME}/fixtures/panic-log-check-output.txt")"
    run summarize_check_output "${check_out}"
    assert_success
    assert_output --regexp '^common/clusterid'
}

@test "removes dates" {
    check_out="$(cat "${BATS_TEST_DIRNAME}/fixtures/panic-log-check-output.txt")"
    run summarize_check_output "${check_out}"
    assert_success
    refute_output --partial '2023/11/16'
}

@test "removes time" {
    check_out="$(cat "${BATS_TEST_DIRNAME}/fixtures/panic-log-check-output.txt")"
    run summarize_check_output "${check_out}"
    assert_success
    refute_output --partial '06:07:58.438015'
}

@test "removes image names" {
    check_out="$(cat "${BATS_TEST_DIRNAME}/fixtures/image-fetch-error-check-output.txt")"
    run summarize_check_output "${check_out}"
    assert_success
    refute_output --partial 'quay.io/rhacs-eng/central-db:4.3.x-168-g03b03c03a9'
}
