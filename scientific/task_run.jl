# ============================================================================
#  AETERNA Scientific Engine — Single Task runner
#  Module: task_run.jl
#  Protocol: AGP-v1
# ============================================================================

using Pkg
Pkg.activate(dirname(@__FILE__))

using JSON3
using Logging
using Random
using SHA
using Statistics

include("oncology_sim.jl")
include("folding_math.jl")

using .OncologySim
using .FoldingMath

const PROTOCOL_VERSION  = "AGP-v1"
const JULIA_VERSION_STR = string(VERSION)

function scientific_hash(obj)::String
    io = IOBuffer()
    JSON3.write(io, obj)
    bytes2hex(sha256(take!(io)))
end

function main()
    if length(ARGS) < 2
        println(stderr, "Usage: julia task_run.jl <input_json> <output_json>")
        exit(1)
    end
    input_path = ARGS[1]
    output_path = ARGS[2]
    
    # Read the input task request
    req = open(input_path, "r") do f
        JSON3.read(read(f, String), Dict{String, Any})
    end
    
    kind   = get(req, "tipo_analisi", "")
    params = get(req, "parametri", Dict{String, Any}())
    repro  = get(req, "reproducibility", Dict{String, Any}())

    seed = get(repro, "seed_rng", 424242)
    Random.seed!(seed)

    t_start = time_ns()
    metrics = if kind == "genome_analysis"
        OncologySim.analizza_genoma(String(get(params, "sequence", "")))
    elseif kind == "genomic_entropy"
        OncologySim.calcola_entropia_genomica(String(get(params, "sequence", "")))
    elseif kind == "dna_mutation_hamming"
        OncologySim.calcola_mutazioni_dna(
            String(get(params, "ref", "")),
            String(get(params, "obs", "")),
        )
    elseif kind == "tumor_growth_gompertz"
        OncologySim.simula_crescita_tumorale(
            Float64(get(params, "N0",    1.0e6)),
            Float64(get(params, "rho",   0.01)),
            Float64(get(params, "K",     1.0e11)),
            Float64(get(params, "sigma", 0.02)),
            Int(get(params, "days", 180)),
        )
    elseif kind == "tumor_therapy_sde"
        OncologySim.simula_terapia_oncologica(
            Float64(get(params, "N0",                1.0e6)),
            Float64(get(params, "rho",               0.01)),
            Float64(get(params, "K",                 1.0e11)),
            Float64(get(params, "sigma",             0.02)),
            Int(get(params, "days",                  180)),
            Float64(get(params, "efficacia_farmaco", 0.35)),
            Int(get(params, "giorno_inizio",          30)),
        )
    elseif kind == "protein_folding_hp"
        FoldingMath.avvia_folding_missione_alpha(
            String(get(params, "sequence", "")),
            Int(get(params, "steps", 50_000)),
        )
    else
        error("tipo_analisi sconosciuto: $(kind)")
    end
    t_elapsed_ms = (time_ns() - t_start) / 1e6

    sci_hash = scientific_hash(metrics)

    reply = Dict{String, Any}(
        "status"             => "ok",
        "protocol_version"   => PROTOCOL_VERSION,
        "julia_version"      => JULIA_VERSION_STR,
        "seed_rng"           => seed,
        "metrics"            => metrics,
        "scientific_hash"    => sci_hash,
        "performance"        => Dict{String, Any}(
            "execution_time_ms" => round(t_elapsed_ms, digits=3),
        ),
    )
    
    # Write the output result
    open(output_path, "w") do f
        JSON3.write(f, reply)
    end
    
    # Sleep loop to keep container alive for PID attestation
    # Will be terminated by the parent (santuario-signer) or timeout in 60s
    t_start_wait = time()
    while time() - t_start_wait < 60.0
        sleep(0.5)
    end
end

main()
