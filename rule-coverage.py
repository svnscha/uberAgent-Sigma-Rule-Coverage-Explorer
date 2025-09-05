#!/usr/bin/env python3
import sys
import os
import json
import yaml
import argparse
import re

from util import utility

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from sigma.backends.uberagent import uberagent as uberagent_backend
from sigma.pipelines.uberagent import uberagent720, uberagent730, uberagent740, uberagent750, uberagent_develop
from sigma.backends.uberagent.exceptions import MissingPropertyException

def get_backends():
    return {
        "uberAgent (develop)": convert_uberagent_develop,
        "uberAgent 7.5": convert_uberagent750,
        "uberAgent 7.4": convert_uberagent740,
        "uberAgent 7.3": convert_uberagent730,
        "uberAgent 7.2": convert_uberagent720
    }


def convert_uberagent720(rule: SigmaCollection):
    return uberagent_backend(processing_pipeline=uberagent720()).convert(rule, "conf")


def convert_uberagent730(rule: SigmaCollection):
    return uberagent_backend(processing_pipeline=uberagent730()).convert(rule, "conf")


def convert_uberagent740(rule: SigmaCollection):
    return uberagent_backend(processing_pipeline=uberagent740()).convert(rule, "conf")


def convert_uberagent750(rule: SigmaCollection):
    return uberagent_backend(processing_pipeline=uberagent750()).convert(rule, "conf")


def convert_uberagent_develop(rule: SigmaCollection):
    return uberagent_backend(processing_pipeline=uberagent_develop()).convert(rule, "conf")


def extract_field(input_string: str):
    # Define the regular expression pattern to find <FIELD>
    pattern = re.compile(r'<(.*?)>')

    # Search for the pattern in the input string
    match = pattern.search(input_string)

    # If a match is found, return the field, otherwise return None
    return match.group(1) if match else None


def test_rule(path: str) -> (dict):
    result: dict = {}
    backends = get_backends()
    for backend in backends.keys():
        convert_function = backends[backend]
        try:
            error = None

            # Need to read the rule collection each processing round to not have orphaned
            # attached processing items.
            rule_collection = SigmaCollection.from_yaml(utility.get_rule(path))
            output = convert_function(rule_collection)
        except SigmaTransformationError as ex:
            if len(ex.args) == 1 and ex.args[0] == 'Rule type not yet supported.':
                pass
            elif len(ex.args) == 1 and 'Cannot transform field' in ex.args[0]:
                field = extract_field(ex.args[0])
                if field is not None:
                    error = { "type": "missing_field", "data": field }
            output = None
        except:
            output = None

        result[backend] = { "status": output is not None and len(output) > 0, "error": error }

    return result


def get_rule(path: str) -> dict:

    def get_rule_yaml(file_path: str) -> dict:
        data = []
        with open(file_path, encoding="utf-8") as f:
            yaml_parts = yaml.safe_load_all(f)
            for part in yaml_parts:
                data.append(part)
        return data

    result = {
        "id": "",
        "title": "",
        "file": "",
        "status": None,
        "level": None,
        "logsource.category": None,
        "logsource.product": None
    }

    rule_yaml = get_rule_yaml(path)
    if len(rule_yaml) != 1:
        raise FileNotFoundError("Rule {} is a multi-document file and will be skipped.".format(path))

    rule_yaml = rule_yaml[0]
    result["id"] = rule_yaml["id"]
    result["title"] = rule_yaml["title"]
    result["file"] = os.path.relpath(path, os.getcwd()).replace("\\", "/")

    if "status" in rule_yaml:
        result["status"] = rule_yaml["status"]

    if "level" in rule_yaml:
        result["level"] = rule_yaml["level"]

    if "logsource" in rule_yaml:
        logsource = rule_yaml["logsource"]
        if "product" in logsource:
            result["logsource.product"] = logsource["product"]
        if "category" in logsource:
            result["logsource.category"] = logsource["category"]

    return result


def main() -> int:

    parser = argparse.ArgumentParser(description="Process the path to the rule directory")
    parser.add_argument('--rules', type=str, required=True, help='This parameter expects a string that specifies the path to the directory where the rules are located.')
    parser.add_argument('--output', type=str, required=True, help='This parameter expects a string that designates the path to the directory where the output file will be stored.')

    args = parser.parse_args()

    output_rules: [] = []
    output_backend_status: dict = {}
    output_error_status: dict = {}
    count = 0

    rule_paths = utility.get_rule_paths(args.rules)
    for rule_path in rule_paths:
        count = count + 1

        print("Processing rule={}".format(rule_path))

        rule = get_rule(rule_path)
        output_rules.append(rule)

        rule_results_for_backends = test_rule(rule_path)
        for backend in rule_results_for_backends.keys():
            rule_result = rule_results_for_backends[backend]
            rule_is_supported = rule_result["status"]

            if not (backend in output_backend_status):
                output_backend_status[backend] = []
            if not (backend in output_error_status):
                output_error_status[backend] = {}

            if rule_is_supported:
                output_backend_status[backend].append(rule["id"])
            else:
                rule_error = rule_result["error"]
                if rule_error is not None:
                    backend_errors = output_error_status.setdefault(backend, {})
                    rule_error_type = rule_error["type"]
                    error_type_dict = backend_errors.setdefault(rule_error_type, {})

                    rule_error_data = rule_error["data"]
                    error_data_dict = error_type_dict.setdefault(rule_error_data, {
                        "refs": [],
                        "logsource.categories": [],
                        "logsource.products": []
                    })

                    # Append the rule ID if it's not already in the refs
                    if rule["id"] not in error_data_dict["refs"]:
                        error_data_dict["refs"].append(rule["id"])

                    # Append the logsource category if it's not already in the categories
                    category = rule["logsource.category"]
                    if category not in error_data_dict["logsource.categories"]:
                        error_data_dict["logsource.categories"].append(category)

                    # Append the logsource product if it's not already in the products
                    product = rule["logsource.product"]
                    if product not in error_data_dict["logsource.products"]:
                        error_data_dict["logsource.products"].append(product)



    with open(args.output, mode="w", encoding="utf-8") as fp:
        json.dump({ "rules": output_rules, "status": output_backend_status, "errors": output_error_status }, fp)

    print("Processed {} rules.".format(count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
