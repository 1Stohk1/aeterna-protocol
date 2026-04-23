# ============================================================================
#  AETERNA Scientific Engine — folding_math.jl
#
#  Protein folding on the 2D HP lattice (Dill's toy model).
#
#  H = hydrophobic, P = polar. The energy of a conformation equals the negative
#  number of H–H topological contacts (non-bonded H residues at lattice-adjacent
#  positions). We minimize via a Monte Carlo Metropolis walk over pivot moves.
#
#  This is NOT protein structure prediction. It is a canonical, reproducible
#  benchmark that exercises the stochastic validation path of AETERNA.
# ============================================================================

module FoldingMath

using Random

export avvia_folding_missione_alpha

const NEIGHBORS = ((1, 0), (-1, 0), (0, 1), (0, -1))

# ----------------------------------------------------------------------------
# Metropolis pivot walk on HP lattice. Returns metrics only.
# ----------------------------------------------------------------------------
function avvia_folding_missione_alpha(seq::AbstractString, steps::Int)::Dict{String, Any}
    upper = uppercase(seq)
    isempty(upper) && throw(ArgumentError("empty sequence"))
    all(c -> c == 'H' || c == 'P', upper) ||
        throw(ArgumentError("HP lattice requires only H/P characters"))

    n     = length(upper)
    coords = _initial_straight_conformation(n)
    best   = copy(coords)
    best_e = _energy(coords, upper)
    current_e = best_e

    T0   = 1.5
    Tend = 0.1
    accepted = 0

    for step in 1:steps
        T = T0 + (Tend - T0) * (step / steps)
        trial = _pivot_move(coords, n)
        isnothing(trial) && continue

        te = _energy(trial::Vector{Tuple{Int, Int}}, upper)
        dE = te - current_e
        if dE <= 0 || rand() < exp(-dE / T)
            coords = trial
            current_e = te
            accepted += 1
            if te < best_e
                best_e = te
                best   = copy(trial)
            end
        end
    end

    return Dict{String, Any}(
        "model"            => "hp_lattice_2d",
        "length"           => n,
        "steps"            => steps,
        "energy_best"      => best_e,
        "energy_final"     => current_e,
        "accept_rate"      => accepted / steps,
        "hh_contacts_best" => -best_e,
        "radius_of_gyration" => _radius_of_gyration(best),
    )
end

# ----------------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------------
function _initial_straight_conformation(n::Int)::Vector{Tuple{Int, Int}}
    return [(i, 0) for i in 1:n]
end

function _pivot_move(coords::Vector{Tuple{Int, Int}}, n::Int)::Union{Vector{Tuple{Int, Int}}, Nothing}
    n < 3 && return nothing
    pivot = rand(2:n-1)
    rot   = rand(1:3)  # 90°, 180°, 270°
    new_coords = similar(coords)
    for i in 1:pivot
        new_coords[i] = coords[i]
    end
    p0 = coords[pivot]
    @inbounds for i in pivot+1:n
        dx = coords[i][1] - p0[1]
        dy = coords[i][2] - p0[2]
        (ndx, ndy) = rot == 1 ? (-dy,  dx) :
                      rot == 2 ? (-dx, -dy) :
                                  ( dy, -dx)
        new_coords[i] = (p0[1] + ndx, p0[2] + ndy)
    end
    _is_self_avoiding(new_coords) ? new_coords : nothing
end

function _is_self_avoiding(coords::Vector{Tuple{Int, Int}})::Bool
    seen = Set{Tuple{Int, Int}}()
    for c in coords
        c in seen && return false
        push!(seen, c)
    end
    return true
end

function _energy(coords::Vector{Tuple{Int, Int}}, seq::AbstractString)::Int
    lookup = Dict{Tuple{Int, Int}, Int}()
    @inbounds for (i, c) in enumerate(coords)
        lookup[c] = i
    end
    contacts = 0
    @inbounds for (i, c) in enumerate(coords)
        seq[i] == 'H' || continue
        for (dx, dy) in NEIGHBORS
            j = get(lookup, (c[1] + dx, c[2] + dy), 0)
            j == 0 && continue
            j > i + 1 && seq[j] == 'H' && (contacts += 1)
        end
    end
    return -contacts
end

function _radius_of_gyration(coords::Vector{Tuple{Int, Int}})::Float64
    n   = length(coords)
    cx  = sum(first, coords) / n
    cy  = sum(last,  coords) / n
    sq  = 0.0
    for (x, y) in coords
        sq += (x - cx)^2 + (y - cy)^2
    end
    return sqrt(sq / n)
end

end  # module FoldingMath
