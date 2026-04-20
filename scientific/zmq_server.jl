# ============================================================================
#  AETERNA Scientific Engine — ZMQ REP dispatcher
#  Module: zmq_server.jl
#  Protocol: AGP-v1
#
#  Six task kinds for Missione Alpha:
#    - genome_analysis        (macro scan: GC + TATA + coarse features)
#    - genomic_entropy        (Shannon H over the sequence)
#    - dna_mutation_hamming   (driver/passenger separation via Hamming)
#    - tumor_growth_gompertz  (base stochastic tumor evolution)
#    - tumor_therapy_sde      (growth + pharmacokinetic pulse)
#    - protein_folding_hp     (HP lattice energy minimization)
#
#  Every reply is deterministic given (tipo_analisi, parametri, seed_rng).
# ============================================================================

using ZMQ
using JSON3
using Logging
using Random
using SHA
using Statistics

include("oncology_sim.jl")
include("folding_math.jl")

using .OncologySim
using .FoldingMath

const ENDPOINT          = get(ENV, "AETERNA_ZMQ_ENDPOINT", "tcp://*:5555")
const PROTOCOL_VERSION  = "AGP-v1"
const JULIA_VERSION_STR = string(VERSION)

# ----------------------------------------------------------------------------
# Canonical hashing for reproducibility attestation.
# ----------------------------------------------------------------------------
function scientific_hash(obj)::String
    io = IOBuffer()
    JSON3.write(io, obj)
    bytes2hex(sha256(take!(io)))
end

# ----------------------------------------------------------------------------
# Dispatcher.
# ----------------------------------------------------------------------------
function dispatch(req::AbstractDict)::Dict{String, Any}
    kind   = get(req, "tipo_analisi", "")
    params = get(req, "parametri", Dict{String, Any}())
    repro  = get(req, "reproducibility", Dict{String, Any}())

    seed = get(repro, "seed_rng", 424242)
    Random.seed!(seed)

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
        throw(ArgumentError("tipo_analisi sconosciuto: $(kind)"))
    end

    sci_hash = scientific_hash(metrics)

    return Dict{String, Any}(
        "status"             => "ok",
        "protocol_version"   => PROTOCOL_VERSION,
        "julia_version"      => JULIA_VERSION_STR,
        "seed_rng"           => seed,
        "metrics"            => metrics,
        "scientific_hash"    => sci_hash,
    )
end

# ----------------------------------------------------------------------------
# Server loop.
# ----------------------------------------------------------------------------
function serve(endpoint::String = ENDPOINT)
    ctx   = Context()
    sock  = Socket(ctx, REP)
    bind(sock, endpoint)
    @info "AETERNA Scientific Engine online" endpoint julia_version=JULIA_VERSION_STR

    try
        while true
            raw = recv(sock)
            reply = try
                req = JSON3.read(String(raw), Dict{String, Any})
                dispatch(req)
            catch err
                Dict{String, Any}(
                    "status" => "error",
                    "error"  => sprint(showerror, err),
                )
            end
            send(sock, JSON3.write(reply))
        end
    catch err
        if err isa InterruptException
            @info "Scientific engine interrupted — graceful shutdown"
        else
            rethrow()
        end
    finally
        close(sock)
        close(ctx)
        @info "ZMQ socket and context released"
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    serve()
end
