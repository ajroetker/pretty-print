# Pretty Print JSON

An example of streaming a POST request in Rust and pretty-printing JSON
response.

~~~bash
    $> cargo build
    ...
    $> ./target/debug/pretty-print http://localhost:8080\pdb\query\v4 \
        --body='{"query":"nodes{ limit 1 }"}'
    [
      {
        "deactivated": null,
        "latest_report_hash": null,
        "facts_environment": "DEV",
        "report_environment": null,
        "catalog_environment": null,
        "facts_timestamp": "2016-02-26T23:41:22.516Z",
        "expired": null,
        "report_timestamp": null,
        "certname": "foo",
        "catalog_timestamp": null,
        "latest_report_status": null
      }
    ]
~~~
