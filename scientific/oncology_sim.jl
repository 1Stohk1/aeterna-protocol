# ============================================================================
#  AETERNA Scientific Engine — oncology_sim.jl
#
#  Sub-modules for Missione Alpha oncology tasks:
#    analizza_genoma                 (genome_analysis)
#    calcola_entropia_genomica       (genomic_entropy)
#    calcola_mutazioni_dna           (dna_mutation_hamming)
#    simula_crescita_tumorale        (tumor_growth_gompertz)
#    simula_terapia_oncologica       (tumor_therapy_sde)
#
#  Deterministic: the caller is expected to have set Random.seed! already.
# ============================================================================

module OncologySim

using Random
using Statistics

export analizza_genoma,
       calcola_entropia_genomica,
       calcola_mutazioni_dna,
       simula_crescita_tumorale,
       simula_terapia_oncologica

const VALID_BASES = Set("ACGT")

# ----------------------------------------------------------------------------
# Macro genomic scan: GC content, TATA box occurrences, N-count.
# ----------------------------------------------------------------------------
function analizza_genoma(seq::AbstractString)::Dict{String, Any}
    upper  = uppercase(seq)
    total  = length(upper)
    gc     = count(c -> c == 'G' || c == 'C', upper)
    at     = count(c -> c == 'A' || c == 'T', upper)
    ns     = count(c -> c ∉ VALID_BASES,       upper)
    tatas  = count(i -> i + 3 <= total && upper[i:i+3] == "TATA", 1:max(1, total - 3))

    return Dict{String, Any}(
        "length"         => total,
        "gc_content"     => total == 0 ? 0.0 : gc / total,
        "at_content"     => total == 0 ? 0.0 : at / total,
        "n_count"        => ns,
        "tata_box_count" => tatas,
    )
end

# ----------------------------------------------------------------------------
# Shannon entropy over nucleotide distribution. Higher = more disordered.
# ----------------------------------------------------------------------------
function calcola_entropia_genomica(seq::AbstractString)::Dict{String, Any}
    upper = uppercase(seq)
    n     = length(upper)
    n == 0 && return Dict("entropy_bits" => 0.0, "length" => 0)

    counts = Dict{Char, Int}()
    for c in upper
        counts[c] = get(counts, c, 0) + 1
    end

    h = 0.0
    for (_, k) in counts
        p  = k / n
        h -= p * log2(p)
    end

    return Dict{String, Any}(
        "entropy_bits"  => h,
        "length"        => n,
        "distribution"  => Dict(string(k) => v / n for (k, v) in counts),
    )
end

# ----------------------------------------------------------------------------
# Hamming distance between reference and observed sequence.
# Positions of divergence are returned so downstream consensus can classify
# driver vs passenger mutations.
# ----------------------------------------------------------------------------
function calcola_mutazioni_dna(ref::AbstractString, obs::AbstractString)::Dict{String, Any}
    length(ref) == length(obs) ||
        throw(ArgumentError("ref and obs must have equal length"))

    positions = Int[]
    mutations = Tuple{Int, Char, Char}[]
    for (i, (r, o)) in enumerate(zip(ref, obs))
        if r != o
            push!(positions, i)
            push!(mutations, (i, r, o))
        end
    end

    n = length(ref)
    return Dict{String, Any}(
        "length"         => n,
        "hamming"        => length(positions),
        "mutation_rate"  => n == 0 ? 0.0 : length(positions) / n,
        "positions"      => positions,
        "mutations"      => [Dict("pos" => p, "ref" => string(r), "obs" => string(o))
                             for (p, r, o) in mutations],
    )
end

# ----------------------------------------------------------------------------
# Euler–Maruyama integration of the Gompertz SDE:
#
#     dN = ρ · N · ln(K / N) · dt  +  σ · N · dW_t
#
# Returns summary metrics only — full trajectories are bandwidth-hostile for
# gossip. If a Guardian wants the whole trace, it issues a follow-up RPC.
# ----------------------------------------------------------------------------
function simula_crescita_tumorale(
    N0::Float64, ρ::Float64, K::Float64, σ::Float64, days::Int;
    dt::Float64 = 0.1,
)::Dict{String, Any}
    steps = max(1, Int(round(days / dt)))
    N     = N0
    series = Vector{Float64}(undef, steps + 1)
    series[1] = N

    @inbounds for i in 1:steps
        dW = sqrt(dt) * randn()
        drift     = ρ * N * log(K / max(N, eps()))
        diffusion = σ * N
        N += drift * dt + diffusion * dW
        N  = max(N, 1.0)   # cells can't drop below one
        series[i + 1] = N
    end

    return Dict{String, Any}(
        "model"         => "gompertz_sde",
        "N0"            => N0,
        "N_final"       => series[end],
        "N_mean"        => mean(series),
        "N_max"         => maximum(series),
        "doubling_days" => _doubling_time(series, dt),
        "days"          => days,
        "dt"            => dt,
        "steps"         => steps,
    )
end

# ----------------------------------------------------------------------------
# Gompertz growth under pharmacological pulse. Drug activates at `giorno_inizio`
# and decays exponentially with a fixed half-life.
# ----------------------------------------------------------------------------
function simula_terapia_oncologica(
    N0::Float64, ρ::Float64, K::Float64, σ::Float64,
    days::Int, efficacia_farmaco::Float64, giorno_inizio::Int;
    dt::Float64 = 0.1,
    drug_halflife_days::Float64 = 5.0,
)::Dict{String, Any}
    steps = max(1, Int(round(days / dt)))
    N     = N0
    decay = log(2.0) / drug_halflife_days
    series = Vector{Float64}(undef, steps + 1)
    series[1] = N

    @inbounds for i in 1:steps
        t_days = i * dt
        dose   = t_days >= giorno_inizio ?
                   efficacia_farmaco * exp(-decay * (t_days - giorno_inizio)) :
                   0.0
        dW = sqrt(dt) * randn()
        drift     = (ρ - dose) * N * log(K / max(N, eps()))
        diffusion = σ * N
        N += drift * dt + diffusion * dW
        N  = max(N, 1.0)
        series[i + 1] = N
    end

    return Dict{String, Any}(
        "model"                => "gompertz_therapy_sde",
        "N0"                   => N0,
        "N_final"              => series[end],
        "N_mean"               => mean(series),
        "N_min"                => minimum(series),
        "efficacia_farmaco"    => efficacia_farmaco,
        "giorno_inizio"        => giorno_inizio,
        "drug_halflife_days"   => drug_halflife_days,
        "days"                 => days,
        "dt"                   => dt,
        "response_ratio"       => series[end] / N0,
    )
end

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function _doubling_time(series::Vector{Float64}, dt::Float64)::Float64
    N0 = series[1]
    target = 2.0 * N0
    for (i, N) in enumerate(series)
        if N >= target
            return (i - 1) * dt
        end
    end
    return NaN
end

end  # module OncologySim
