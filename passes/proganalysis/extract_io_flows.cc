/*
 *  yosys -- Yosys Open SYnthesis Suite
 *
 *  Copyright (C) 2012  Claire Xenia Wolf <claire@yosyshq.com>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

 #include "kernel/register.h"
 #include "kernel/ffinit.h"
 #include "kernel/sigtools.h"
 #include "kernel/log.h"
 #include "kernel/celltypes.h"
 #include "kernel/json.h"
 #include "libs/sha1/sha1.h"
 #include <stdlib.h>
 #include <stdio.h>
 #include <set>
 #include <cassert>
 
 
 USING_YOSYS_NAMESPACE
 PRIVATE_NAMESPACE_BEGIN
 
 struct ExtractIOFlowsWorker
 {
	 RTLIL::Module *module;
	 dict<RTLIL::SigBit, std::set<RTLIL::SigBit>> sig_inputs;
	 dict<RTLIL::SigBit, std::set<RTLIL::SigBit>> sig_deps;
 
	 void add_sigbit_connection(RTLIL::SigBit src, RTLIL::SigBit dest)
	 {
		 sig_inputs[dest].insert(src);
	 }
 
	 std::set<RTLIL::SigBit> &get_dependencies(RTLIL::SigBit sig)
	 {
		 if (sig_deps.count(sig))
			 return sig_deps.at(sig);
 
		 auto deps = std::set<RTLIL::SigBit>();
 
		 if (!sig.is_wire())
			 return sig_deps[sig] = deps;
 
		 if (sig.wire->port_input) {
			 deps.insert(sig);
			 return sig_deps[sig] = deps;
		 }
 
		 for (auto pred: sig_inputs[sig])
			 for (auto pred_dep: get_dependencies(pred))
				 deps.insert(pred_dep);
 
		 return sig_deps[sig] = deps;
	 }
 
	 ExtractIOFlowsWorker(RTLIL::Design *design, RTLIL::Module *module) : module(module)
	 {
		 for (auto conn: module->connections()) {
			 auto dest = conn.first;
			 auto src = conn.second;
			 log_assert(dest.size() == src.size());
			 for (int i = 0; i < dest.size(); i++) {
				 auto dest_bit = dest[i];
				 auto src_bit = src[i];
				 add_sigbit_connection(src_bit, dest_bit);
			 }
		 }
 
		 for (auto cell : module->cells()) {
			 RTLIL::SigSpec inputs, outputs;
			 if (cell->type == "$scopeinfo") continue;
			 log_assert(cell->type == "$_XOR_" || cell->type == "$_AND_" || cell->type == "$_OR_" || cell->type == "$_NOT_" || cell->type == "$_MUX_");
			 for (auto conn : cell->connections()) {
				 auto dest = conn.first;
				 auto src = conn.second;
				 log_assert(src.size() == 1);
				 if (dest == "\\Y") {
					 outputs.append(src);
					 continue;
				 } else {
					 log_assert(dest == "\\A" || dest == "\\B" || dest == "\\S");
					 inputs.append(src);
					 continue;
				 }
			 }
			 for (int i = 0; i < outputs.size(); i++) {
				 auto output = outputs[i];
				 for (int j = 0; j < inputs.size(); j++) {
					 auto input = inputs[j];
					 add_sigbit_connection(input, output);
				 }
			 }
		 }
 
		 PrettyJson json;
		 json.emit_to_log();
		 json.begin_object();
		 json.entry("module", module->name.str());
		 json.entry("inputs", get_json_inputs_list());
		 json.entry_json("outputs", get_json_outputs_list());
		 json.entry_json("dependencies", get_json_dependencies_dict());
		 json.end_object();
		 // log("HAHAHAHHA");
 
		 // for (auto port: module->ports) {
		 // 	auto wire = module->wire(port);
		 // 	if (!wire->port_output) continue;
		 // 	for (int offset = 0; offset < wire->width; offset++) {
		 // 		auto bit = RTLIL::SigBit(wire, offset);
		 // 		auto deps = get_dependencies(bit);
		 // 		log("Output %s[%d] has %d dependencies\n", wire->name.c_str(), offset, deps.size());
		 // 		for (auto dep: deps) {
		 // 			log("  %s\n", log_signal(dep));
		 // 		}
		 // 	}
		 // }
	 }
 
	 json11::Json get_json_inputs_list()
	 {
		 json11::Json json;
		 std::vector<json11::Json> inputs;
		 for (auto port: module->ports) {
			 auto wire = module->wire(port);
			 if (!wire->port_input) continue;
			 for (int offset = 0; offset < wire->width; offset++) {
				 auto bit = RTLIL::SigBit(wire, offset);
				 inputs.push_back(Json::object({
					 {"name", wire->name.str()},
					 {"offset", offset},
					 {"width", wire->width},
				 }));
			 }
		 }
		 return inputs;
	 }
 
	 json11::Json get_json_outputs_list()
	 {
		 json11::Json json;
		 std::vector<json11::Json> outputs;
		 for (auto port: module->ports) {
			 auto wire = module->wire(port);
			 if (!wire->port_output) continue;
			 for (int offset = 0; offset < wire->width; offset++) {
				 auto bit = RTLIL::SigBit(wire, offset);
				 outputs.push_back(Json::object({
				   {"name", wire->name.str()},
				   {"offset", offset},
				   {"width", wire->width},
				 }));
			 }
		 }
		 return outputs;
	 }
 
	 json11::Json get_json_dependencies_dict()
	 {
		 std::map<std::string, json11::Json> deps;
		 for (auto port: module->ports) {
			 auto wire = module->wire(port);
			 if (!wire->port_output)
				 continue;
			 for (int offset = 0; offset < wire->width; offset++) {
				 auto sig_deps = get_dependencies(RTLIL::SigBit(wire, offset));
				 std::vector<json11::Json> dep_names;
				 for (auto dep : sig_deps) {
					 dep_names.push_back(Json::object({
					   {"name", dep.wire->name.str()},
					   {"offset", dep.offset},
					   {"width", dep.wire->width},
					 }));
				 }
				 deps[wire->name.str() + "[" + std::to_string(offset) + "]"] = dep_names;
			 }
		 }
		 return deps;
	 }
 };
 
 std::vector<std::string> SEQ_ELEMENTS ={"FF", "DLATCH", "DLE", "SR", "mem"};
 
 struct ExtractIOFlowsPass : public Pass {
	 ExtractIOFlowsPass() : Pass("extract_io_flows", "extract the inputs that flow into outputs") { }
	 int is_sequential(Cell *cell)
	 {
		 for (auto element: SEQ_ELEMENTS)
		 {
			 if(cell->type.str().find(element) != std::string::npos)
				 return 1;
		 }
		 return 0;
	 }
	 void help() override
	 {
		 //   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		 log("\n");
		 log("    extract_io_flows\n");
		 log("\n");
	 }
	 void execute(std::vector<std::string> args, RTLIL::Design *design) override
	 {
		 log_header(design, "Executing EXTRACT_IO_FLOWS pass.\n");
 
		 if (args.size() != 1) {
			 log("No options supported yet.\n");
			 log("\n");
		 }
 
		 for (auto module : design->selected_modules()) {
			 int is_seq=0;
			 for (auto cell : module->cells()){
				 if (is_sequential(cell)){
					 is_seq=1;
					 log("Sequential cell found: %s\n", cell->type.c_str());
					 break;
				 }
			 }
			 if (is_seq){
				 log("No I/O Flow analysis for sequential module %s yet.\n", module->name.c_str());
				 log("\n");
			 }
			 else{
				 log("Analysing Combinational module %s.\n", module->name.c_str());
				 log("\n");
				 // for (auto &cell_it : module->cells_)
				 // {
				 // 	RTLIL::Cell *cell = cell_it.second;
				 // 	log("Module: %s, Cell Type: %s\n", module->name.c_str(), cell->type.str().c_str());
				 // }
 
				 ExtractIOFlowsWorker worker(design, module);
			 }
		 }
	 }
 } ExtractIOFlowsPass;
 
 PRIVATE_NAMESPACE_END
 